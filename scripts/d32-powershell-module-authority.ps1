# Candidate-owned, module-free bootstrap for strict D32 PowerShell module admission.
# This file intentionally uses only PowerShell Core/.NET APIs until every pin and
# content fence has passed. It does not trust ambient module search paths.
$script:D32PowerShellAuthorityPreparationDeadlineTicks = 0L
$script:D32PowerShellAuthorityTrustedRuntimeRoot = [IO.Path]::GetFullPath([IO.Path]::Combine(
    [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles), 'PowerShell', '7'))
$script:D32PowerShellAdmissionDirectoryFences = $null
$script:D32PowerShellAuthorityTestProvider = $null
$script:D32PowerShellModuleAdmissionValidationContext = 'record.not-started'
$script:D32PowerShellModuleAdmissionValidationDetail = $null

function Get-D32PowerShellAuthorityFixedProgramFilesRuntimeRoot {
    $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    if ([string]::IsNullOrWhiteSpace([string]$programFiles)) {
        throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: fixed Program Files runtime root is unavailable'
    }
    return [IO.Path]::GetFullPath([IO.Path]::Combine([string]$programFiles, 'PowerShell', '7'))
}

function Get-D32PowerShellAuthorityTrustedRuntimeRoot {
    $fixedRoot = Get-D32PowerShellAuthorityFixedProgramFilesRuntimeRoot
    $configuredRoot = [string]$script:D32PowerShellAuthorityTrustedRuntimeRoot
    if ([string]::IsNullOrWhiteSpace($configuredRoot) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath($configuredRoot),$fixedRoot)) {
        throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: trusted runtime root is not the fixed Program Files PowerShell 7 root'
    }
    return $fixedRoot
}

function Test-D32PowerShellAuthorityPathNoReparse {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($null -ne $script:D32PowerShellAuthorityTestProvider -and $null -ne $script:D32PowerShellAuthorityTestProvider.NoReparse) {
        return [bool](& $script:D32PowerShellAuthorityTestProvider.NoReparse -Path $Path)
    }
    try {
        $full = [IO.Path]::GetFullPath($Path)
        $root = [IO.Path]::GetPathRoot($full)
        if ([String]::IsNullOrWhiteSpace($root)) { return $false }
        $current = $root
        $parts = @($full.Substring($root.Length) -split '[\\/]+' )
        foreach ($part in $parts) {
            if ([String]::IsNullOrWhiteSpace($part)) { continue }
            $current = [IO.Path]::Combine($current, $part)
            $attributes = [IO.File]::GetAttributes($current)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
        }
        return $true
    }
    catch { return $false }
}

function Assert-D32PowerShellAuthorityPreparationDeadline {
    if ([long]$script:D32PowerShellAuthorityPreparationDeadlineTicks -gt 0 -and
        [Diagnostics.Stopwatch]::GetTimestamp() -ge [long]$script:D32PowerShellAuthorityPreparationDeadlineTicks) {
        throw 'POWERSHELL_MODULE_AUTHORITY_BUDGET_STOPPED: fixed preparation wall deadline reached; candidate cannot succeed'
    }
}

function Test-D32PowerShellAuthorityPathWithin {
    param([Parameter(Mandatory = $true)][string]$Child, [Parameter(Mandatory = $true)][string]$Parent)
    if ($Child -isnot [string] -or $Parent -isnot [string] -or
        [String]::IsNullOrWhiteSpace([string]$Child) -or [String]::IsNullOrWhiteSpace([string]$Parent) -or
        -not [IO.Path]::IsPathFullyQualified([string]$Child) -or -not [IO.Path]::IsPathFullyQualified([string]$Parent)) { return $false }
    try {
        $childFull = [IO.Path]::GetFullPath([string]$Child)
        $parentFull = [IO.Path]::GetFullPath([string]$Parent)
        $childRoot = [IO.Path]::GetPathRoot($childFull)
        $parentRoot = [IO.Path]::GetPathRoot($parentFull)
        if ([String]::IsNullOrWhiteSpace($childRoot) -or [String]::IsNullOrWhiteSpace($parentRoot)) { return $false }
        $childComparable = if ($childFull.Length -gt $childRoot.Length) { $childFull.TrimEnd('\', '/') } else { $childRoot }
        $parentComparable = if ($parentFull.Length -gt $parentRoot.Length) { $parentFull.TrimEnd('\', '/') } else { $parentRoot }
        if ([StringComparer]::OrdinalIgnoreCase.Equals($childComparable, $parentComparable)) { return $true }
        $parentIsRoot = [StringComparer]::OrdinalIgnoreCase.Equals($parentComparable, $parentRoot) -or
            [StringComparer]::OrdinalIgnoreCase.Equals($parentComparable.TrimEnd('\', '/'), $parentRoot.TrimEnd('\', '/'))
        $parentPrefix = if ($parentIsRoot) {
            if ($parentRoot.EndsWith([IO.Path]::DirectorySeparatorChar)) { $parentRoot } else { $parentRoot + [IO.Path]::DirectorySeparatorChar }
        } else { $parentComparable + [IO.Path]::DirectorySeparatorChar }
        return $childFull.StartsWith($parentPrefix, [StringComparison]::OrdinalIgnoreCase)
    }
    catch { return $false }
}

function Initialize-D32PowerShellAuthorityNativeApi {
    if ('D32PowerShellModuleNativeV2' -as [type]) { return }
    $assemblyName = [Reflection.AssemblyName]::new('D32PowerShellModuleNativeV2')
    $assembly = [Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly($assemblyName, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $module = $assembly.DefineDynamicModule('D32PowerShellModuleNativeV2')
    $type = $module.DefineType('D32PowerShellModuleNativeV2', [Reflection.TypeAttributes]::Public -bor [Reflection.TypeAttributes]::Abstract -bor [Reflection.TypeAttributes]::Sealed)
    $createFile = $type.DefinePInvokeMethod('CreateFileW', 'kernel32.dll', [Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static -bor [Reflection.MethodAttributes]::PinvokeImpl,
        [Reflection.CallingConventions]::Standard, [Microsoft.Win32.SafeHandles.SafeFileHandle],
        [type[]]@([string], [uint32], [uint32], [IntPtr], [uint32], [uint32], [IntPtr]),
        [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Unicode)
    $createFile.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
    $getInfo = $type.DefinePInvokeMethod('GetFileInformationByHandle', 'kernel32.dll', [Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static -bor [Reflection.MethodAttributes]::PinvokeImpl,
        [Reflection.CallingConventions]::Standard, [bool],
        [type[]]@([Microsoft.Win32.SafeHandles.SafeFileHandle], [IntPtr]),
        [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Auto)
    $getInfo.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
    $getFileIdInfo = $type.DefinePInvokeMethod('GetFileInformationByHandleEx', 'kernel32.dll', [Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static -bor [Reflection.MethodAttributes]::PinvokeImpl,
        [Reflection.CallingConventions]::Standard, [bool],
        [type[]]@([Microsoft.Win32.SafeHandles.SafeFileHandle], [int], [IntPtr], [uint32]),
        [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Auto)
    $getFileIdInfo.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
    $getFinalPath = $type.DefinePInvokeMethod('GetFinalPathNameByHandleW', 'kernel32.dll', [Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static -bor [Reflection.MethodAttributes]::PinvokeImpl,
        [Reflection.CallingConventions]::Standard, [uint32],
        [type[]]@([Microsoft.Win32.SafeHandles.SafeFileHandle], [Text.StringBuilder], [uint32], [uint32]),
        [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Unicode)
    $getFinalPath.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
    $setDefaultDirectories = $type.DefinePInvokeMethod('SetDefaultDllDirectories', 'kernel32.dll', [Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static -bor [Reflection.MethodAttributes]::PinvokeImpl,
        [Reflection.CallingConventions]::Standard, [bool], [type[]]@([uint32]),
        [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Auto)
    $setDefaultDirectories.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
    $setDllDirectory = $type.DefinePInvokeMethod('SetDllDirectoryW', 'kernel32.dll', [Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static -bor [Reflection.MethodAttributes]::PinvokeImpl,
        [Reflection.CallingConventions]::Standard, [bool], [type[]]@([string]),
        [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Unicode)
    $setDllDirectory.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
    $getDllDirectory = $type.DefinePInvokeMethod('GetDllDirectoryW', 'kernel32.dll', [Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static -bor [Reflection.MethodAttributes]::PinvokeImpl,
        [Reflection.CallingConventions]::Standard, [uint32], [type[]]@([uint32], [Text.StringBuilder]),
        [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Unicode)
    $getDllDirectory.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
    $getWindowsDirectory = $type.DefinePInvokeMethod('GetWindowsDirectoryW', 'kernel32.dll', [Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static -bor [Reflection.MethodAttributes]::PinvokeImpl,
        [Reflection.CallingConventions]::Standard, [uint32], [type[]]@([Text.StringBuilder], [uint32]),
        [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Unicode)
    $getWindowsDirectory.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
    $getTokenInformation = $type.DefinePInvokeMethod('GetTokenInformation', 'advapi32.dll', [Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static -bor [Reflection.MethodAttributes]::PinvokeImpl,
        [Reflection.CallingConventions]::Standard, [bool], [type[]]@([IntPtr], [int], [IntPtr], [uint32], [IntPtr]),
        [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Auto)
    $getTokenInformation.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
    $winTrustPath = [IO.Path]::GetFullPath([IO.Path]::Combine([string]$env:SystemRoot, 'System32', 'wintrust.dll'))
    $winVerifyTrust = $type.DefinePInvokeMethod('WinVerifyTrust', $winTrustPath, [Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static -bor [Reflection.MethodAttributes]::PinvokeImpl,
        [Reflection.CallingConventions]::Standard, [int], [type[]]@([IntPtr], [IntPtr], [IntPtr]),
        [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Unicode)
    $winVerifyTrust.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
    $getModuleHandle = $type.DefinePInvokeMethod('GetModuleHandleW', 'kernel32.dll', [Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static -bor [Reflection.MethodAttributes]::PinvokeImpl,
        [Reflection.CallingConventions]::Standard, [IntPtr], [type[]]@([string]),
        [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Unicode)
    $getModuleHandle.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
    $getProcAddress = $type.DefinePInvokeMethod('GetProcAddress', 'kernel32.dll', [Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static -bor [Reflection.MethodAttributes]::PinvokeImpl,
        [Reflection.CallingConventions]::Standard, [IntPtr], [type[]]@([IntPtr], [string]),
        [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Ansi)
    $getProcAddress.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
    $virtualQuery = $type.DefinePInvokeMethod('VirtualQuery', 'kernel32.dll', [Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static -bor [Reflection.MethodAttributes]::PinvokeImpl,
        [Reflection.CallingConventions]::Standard, [UIntPtr], [type[]]@([IntPtr], [IntPtr], [UIntPtr]),
        [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Auto)
    $virtualQuery.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
    $getModuleFileName = $type.DefinePInvokeMethod('GetModuleFileNameW', 'kernel32.dll', [Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static -bor [Reflection.MethodAttributes]::PinvokeImpl,
        [Reflection.CallingConventions]::Standard, [uint32], [type[]]@([IntPtr], [Text.StringBuilder], [uint32]),
        [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Unicode)
    $getModuleFileName.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
    $getTickCount64 = $type.DefinePInvokeMethod('GetTickCount64', 'kernel32.dll', [Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static -bor [Reflection.MethodAttributes]::PinvokeImpl,
        [Reflection.CallingConventions]::Standard, [UInt64], [type[]]@(),
        [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Auto)
    $getTickCount64.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
    $null = $type.CreateType()
}

function Get-D32PowerShellAuthorityAuthenticodeSourceProof {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not [Environment]::Is64BitProcess) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: Windows source verification requires the pinned x64 process' }
    Initialize-D32PowerShellAuthorityNativeApi
    $full = [IO.Path]::GetFullPath($Path)
    $certificate = $null
    $pathPointer = [IntPtr]::Zero
    $fileInfo = [IntPtr]::Zero
    $trustData = [IntPtr]::Zero
    $actionPointer = [IntPtr]::Zero
    try {
        $signedCertificate = [Security.Cryptography.X509Certificates.X509Certificate]::CreateFromSignedFile($full)
        try { $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($signedCertificate) }
        finally { if ($null -ne $signedCertificate) { $signedCertificate.Dispose() } }
        $pathPointer = [Runtime.InteropServices.Marshal]::StringToHGlobalUni($full)
        $fileInfo = [Runtime.InteropServices.Marshal]::AllocHGlobal(32)
        $trustData = [Runtime.InteropServices.Marshal]::AllocHGlobal(88)
        $actionPointer = [Runtime.InteropServices.Marshal]::AllocHGlobal(16)
        # WINTRUST_DATA includes the trailing pSignatureSettings member on
        # supported Windows versions. AllocHGlobal is not zero-initializing;
        # clear the complete ABI records before writing fields so an
        # indeterminate trailing pointer cannot be dereferenced by wintrust.
        [Runtime.InteropServices.Marshal]::Copy([byte[]]::new(32), 0, $fileInfo, 32)
        [Runtime.InteropServices.Marshal]::Copy([byte[]]::new(88), 0, $trustData, 88)
        [Runtime.InteropServices.Marshal]::StructureToPtr([Guid]'00AAC56B-CD44-11d0-8CC2-00C04FC295EE', $actionPointer, $false)
        [Runtime.InteropServices.Marshal]::WriteInt32($fileInfo, 0, 32)
        [Runtime.InteropServices.Marshal]::WriteIntPtr($fileInfo, 8, $pathPointer)
        [Runtime.InteropServices.Marshal]::WriteIntPtr($fileInfo, 16, [IntPtr]::Zero)
        [Runtime.InteropServices.Marshal]::WriteIntPtr($fileInfo, 24, [IntPtr]::Zero)
        [Runtime.InteropServices.Marshal]::WriteInt32($trustData, 0, 88)
        [Runtime.InteropServices.Marshal]::WriteIntPtr($trustData, 8, [IntPtr]::Zero)
        [Runtime.InteropServices.Marshal]::WriteIntPtr($trustData, 16, [IntPtr]::Zero)
        [Runtime.InteropServices.Marshal]::WriteInt32($trustData, 24, 2) # WTD_UI_NONE
        [Runtime.InteropServices.Marshal]::WriteInt32($trustData, 28, 0) # WTD_REVOKE_NONE; no network retrieval
        [Runtime.InteropServices.Marshal]::WriteInt32($trustData, 32, 1) # WTD_CHOICE_FILE
        [Runtime.InteropServices.Marshal]::WriteIntPtr($trustData, 40, $fileInfo)
        [Runtime.InteropServices.Marshal]::WriteInt32($trustData, 48, 1) # WTD_STATEACTION_VERIFY
        [Runtime.InteropServices.Marshal]::WriteIntPtr($trustData, 56, [IntPtr]::Zero)
        [Runtime.InteropServices.Marshal]::WriteIntPtr($trustData, 64, [IntPtr]::Zero)
        [Runtime.InteropServices.Marshal]::WriteInt32($trustData, 72, 0x1000) # WTD_CACHE_ONLY_URL_RETRIEVAL
        [Runtime.InteropServices.Marshal]::WriteInt32($trustData, 76, 0)
        if ([D32PowerShellModuleNativeV2]::WinVerifyTrust([IntPtr]::Zero, $actionPointer, $trustData) -ne 0) {
            throw 'signature trust provider did not validate using cache-only policy'
        }
        $subject = [string]$certificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        $issuer = [string]$certificate.IssuerName.Name
        if ($subject -cne 'Microsoft Windows' -or $issuer -cnotlike 'CN=Windows Production PCA 2023,*') {
            throw 'signature publisher or issuing chain differs from the pinned Defender Windows source'
        }
        $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($full)
        if ($version.CompanyName -cne 'Microsoft Corporation' -or [String]::IsNullOrWhiteSpace($version.ProductVersion)) {
            throw 'signed image product metadata is not the expected Microsoft Windows platform metadata'
        }
        return [ordered]@{
            proof_type = 'WINTRUST_CACHE_ONLY_AUTHENTICODE_V1'
            signature_status = 'VALID'
            signer_simple_name = $subject
            issuer_name = $issuer
            signer_thumbprint = [string]$certificate.Thumbprint.ToLowerInvariant()
            company_name = [string]$version.CompanyName
            product_name = [string]$version.ProductName
            product_version = [string]$version.ProductVersion
            file_version = [string]$version.FileVersion
        }
    }
    catch { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: Defender Authenticode source proof failed for $full : $($_.Exception.Message)" }
    finally {
        if ($null -ne $trustData -and $trustData -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::WriteInt32($trustData, 48, 2) # WTD_STATEACTION_CLOSE
            $null = [D32PowerShellModuleNativeV2]::WinVerifyTrust([IntPtr]::Zero, $actionPointer, $trustData)
        }
        if ($null -ne $certificate) { $certificate.Dispose() }
        if ($actionPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($actionPointer) }
        if ($trustData -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($trustData) }
        if ($fileInfo -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($fileInfo) }
        if ($pathPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($pathPointer) }
    }
}

function Get-D32PowerShellAuthorityWindowsRootPath {
    Initialize-D32PowerShellAuthorityNativeApi
    $buffer = [Text.StringBuilder]::new(32768)
    $length = [D32PowerShellModuleNativeV2]::GetWindowsDirectoryW($buffer, [uint32]$buffer.Capacity)
    if ($length -le 0 -or $length -ge $buffer.Capacity) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: Windows OS directory identity API returned no bounded path' }
    $apiPath = [IO.Path]::GetFullPath($buffer.ToString())
    $environmentPath = [IO.Path]::GetFullPath([string]$env:SystemRoot)
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($apiPath, $environmentPath) -or -not (Test-D32PowerShellAuthorityPathNoReparse -Path $apiPath)) {
        throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: process SystemRoot does not bind the OS directory API and non-reparse namespace'
    }
    return $apiPath
}

function Get-D32PowerShellAuthorityNativeUptimeOriginEvidence {
    param(
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$DirectoryFences,
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[object]]$OpenFiles,
        [Parameter(Mandatory = $true)][long]$DeadlineTicks
    )
    if ($DeadlineTicks -le 0 -or [Diagnostics.Stopwatch]::GetTimestamp() -ge $DeadlineTicks) {
        throw 'POWERSHELL_MODULE_AUTHORITY_BUDGET_STOPPED: fixed uptime-origin capture is not admitted or is late'
    }
    Initialize-D32PowerShellAuthorityNativeApi
    $systemRoot = [IO.Path]::GetFullPath((Get-D32PowerShellAuthorityWindowsRootPath))
    $system32 = [IO.Path]::GetFullPath([IO.Path]::Combine($systemRoot, 'System32'))
    $kernel32 = [D32PowerShellModuleNativeV2]::GetModuleHandleW('kernel32.dll')
    if ($kernel32 -eq [IntPtr]::Zero) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: actual kernel32 module handle is unavailable' }
    $apiAddress = [D32PowerShellModuleNativeV2]::GetProcAddress($kernel32, 'GetTickCount64')
    if ($apiAddress -eq [IntPtr]::Zero) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: actual kernel32 GetTickCount64 export is unavailable' }
    $memory = [IntPtr]::Zero
    $memoryInformationSize = if ([Environment]::Is64BitProcess) { 48 } else { 28 }
    $allocationBaseOffset = if ([Environment]::Is64BitProcess) { 8 } else { 4 }
    $memoryTypeOffset = if ([Environment]::Is64BitProcess) { 40 } else { 24 }
    $openedImages = [System.Collections.Generic.List[object]]::new()
    try {
        $memory = [Runtime.InteropServices.Marshal]::AllocHGlobal($memoryInformationSize)
        [Runtime.InteropServices.Marshal]::Copy([byte[]]::new($memoryInformationSize), 0, $memory, $memoryInformationSize)
        $kernelQuery = [D32PowerShellModuleNativeV2]::VirtualQuery($kernel32, $memory, [UIntPtr]$memoryInformationSize)
        if ($kernelQuery.ToUInt64() -ne $memoryInformationSize -or
            [Runtime.InteropServices.Marshal]::ReadInt32($memory, $memoryTypeOffset) -ne 0x01000000 -or
            [Runtime.InteropServices.Marshal]::ReadIntPtr($memory, $allocationBaseOffset) -ne $kernel32) {
            throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: actual kernel32 export module is not a MEM_IMAGE allocation'
        }
        [Runtime.InteropServices.Marshal]::Copy([byte[]]::new($memoryInformationSize), 0, $memory, $memoryInformationSize)
        $targetQuery = [D32PowerShellModuleNativeV2]::VirtualQuery($apiAddress, $memory, [UIntPtr]$memoryInformationSize)
        if ($targetQuery.ToUInt64() -ne $memoryInformationSize -or
            [Runtime.InteropServices.Marshal]::ReadInt32($memory, $memoryTypeOffset) -ne 0x01000000) {
            throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: GetTickCount64 export target is not a MEM_IMAGE allocation'
        }
        $targetBase = [Runtime.InteropServices.Marshal]::ReadIntPtr($memory, $allocationBaseOffset)
        if ($targetBase -eq [IntPtr]::Zero) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: GetTickCount64 export target image base is null' }
        $kernelPathBuffer = [Text.StringBuilder]::new(32768)
        $kernelPathChars = [D32PowerShellModuleNativeV2]::GetModuleFileNameW($kernel32, $kernelPathBuffer, [uint32]$kernelPathBuffer.Capacity)
        $targetPathBuffer = [Text.StringBuilder]::new(32768)
        $targetPathChars = [D32PowerShellModuleNativeV2]::GetModuleFileNameW($targetBase, $targetPathBuffer, [uint32]$targetPathBuffer.Capacity)
        if ($kernelPathChars -le 0 -or $kernelPathChars -ge $kernelPathBuffer.Capacity -or
            $targetPathChars -le 0 -or $targetPathChars -ge $targetPathBuffer.Capacity) {
            throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: actual export image paths exceed the fixed native path bound'
        }
        $kernelPath = [IO.Path]::GetFullPath($kernelPathBuffer.ToString())
        $targetPath = [IO.Path]::GetFullPath($targetPathBuffer.ToString())
        if (-not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName($kernelPath), $system32) -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName($targetPath), $system32) -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFileName($kernelPath), 'kernel32.dll')) {
            throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: kernel32 export or resolved target is outside the fixed System32 OS directory'
        }
        foreach ($path in @($kernelPath, $targetPath) | Select-Object -Unique) {
            Assert-D32PowerShellAuthorityPreparationDeadline
            $snapshot = Open-D32PowerShellAuthorityFile -Path $path -DirectoryFences $DirectoryFences -MaximumBytes 268435456L -DeadlineTicks $DeadlineTicks
            $OpenFiles.Add($snapshot); $openedImages.Add($snapshot)
            if (-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $snapshot.Security -IsDirectory:$false)) {
                throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: loaded GetTickCount64 image is not in a protected OS namespace'
            }
            $proof = Get-D32PowerShellAuthorityAuthenticodeSourceProof -Path $path
            if ([string]$proof.signature_status -cne 'VALID' -or [string]$proof.signer_simple_name -cne 'Microsoft Windows' -or
                [string]$proof.company_name -cne 'Microsoft Corporation') {
                throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: loaded uptime export image does not have the fixed Microsoft OS source proof'
            }
            $snapshot | Add-Member -NotePropertyName SourceProof -NotePropertyValue $proof -Force
            Assert-D32PowerShellAuthorityPreparationDeadline
        }
        $kernelSnapshot = @($openedImages | Where-Object { [StringComparer]::OrdinalIgnoreCase.Equals([string]$_.Record.path, $kernelPath) })[0]
        $targetSnapshot = @($openedImages | Where-Object { [StringComparer]::OrdinalIgnoreCase.Equals([string]$_.Record.path, $targetPath) })[0]
        if ($null -eq $kernelSnapshot -or $null -eq $targetSnapshot) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: loaded uptime export file pins are incomplete' }
        $uptime = [D32PowerShellModuleNativeV2]::GetTickCount64()
        Assert-D32PowerShellAuthorityPreparationDeadline
        return [ordered]@{
            api = 'kernel32!GetTickCount64'; return_type = 'System.UInt64'; value_milliseconds = [UInt64]$uptime
            kernel32_export_image = [ordered]@{ file = $kernelSnapshot.Record; source_proof = $kernelSnapshot.SourceProof
                module_base_hex = ('0x' + ([UInt64]$kernel32.ToInt64()).ToString('x16')) }
            actual_target_image = [ordered]@{ file = $targetSnapshot.Record; source_proof = $targetSnapshot.SourceProof
                allocation_base_hex = ('0x' + ([UInt64]$targetBase.ToInt64()).ToString('x16'))
                export_address_hex = ('0x' + ([UInt64]$apiAddress.ToInt64()).ToString('x16')); memory_type = 'MEM_IMAGE' }
        }
    } finally {
        if ($memory -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($memory) }
    }
}

function Get-D32PowerShellAuthorityCurrentToken {
    $threadIdentity = $null
    $processIdentity = $null
    $elevationBuffer = [IntPtr]::Zero
    $integrityBuffer = [IntPtr]::Zero
    $returnLength = [IntPtr]::Zero
    try {
        $threadIdentity = [Security.Principal.WindowsIdentity]::GetCurrent($true)
        if ($null -ne $threadIdentity) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: thread impersonation is not accepted during module admission' }
        $processIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        if ($null -eq $processIdentity -or $null -eq $processIdentity.Token -or $processIdentity.Token -eq [IntPtr]::Zero -or $null -eq $processIdentity.User) {
            throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: current process token identity is unavailable'
        }
        Initialize-D32PowerShellAuthorityNativeApi
        $elevationBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal(4)
        $integrityBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal(256)
        $returnLength = [Runtime.InteropServices.Marshal]::AllocHGlobal(4)
        if (-not [D32PowerShellModuleNativeV2]::GetTokenInformation($processIdentity.Token, 20, $elevationBuffer, 4, $returnLength) -or
            [Runtime.InteropServices.Marshal]::ReadInt32($returnLength) -ne 4) {
            throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: process token elevation state is unavailable'
        }
        $isElevated = [Runtime.InteropServices.Marshal]::ReadInt32($elevationBuffer) -ne 0
        if (-not [D32PowerShellModuleNativeV2]::GetTokenInformation($processIdentity.Token, 25, $integrityBuffer, 256, $returnLength) -or
            [Runtime.InteropServices.Marshal]::ReadInt32($returnLength) -le 0 -or [Runtime.InteropServices.Marshal]::ReadInt32($returnLength) -gt 256) {
            throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: process token integrity level is unavailable'
        }
        $sid = [Runtime.InteropServices.Marshal]::ReadIntPtr($integrityBuffer)
        if ($sid -eq [IntPtr]::Zero) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: process token integrity SID is unavailable' }
        $subAuthorityCount = [Runtime.InteropServices.Marshal]::ReadByte($sid, 1)
        if ($subAuthorityCount -lt 1 -or $subAuthorityCount -gt 15) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: process token integrity SID is malformed' }
        $integrityOffset = 8 + (4 * ($subAuthorityCount - 1))
        $returnedBytes = [Runtime.InteropServices.Marshal]::ReadInt32($returnLength)
        $bufferStart = $integrityBuffer.ToInt64()
        $sidStart = $sid.ToInt64()
        if ($sidStart -lt $bufferStart -or ($sidStart + $integrityOffset + 4) -gt ($bufferStart + $returnedBytes)) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: process token integrity SID exceeds its returned buffer' }
        $integrityRid = [uint32][Runtime.InteropServices.Marshal]::ReadInt32($sid, $integrityOffset)
        $isSystem = [string]$processIdentity.User.Value -ceq 'S-1-5-18'
        if ($isElevated -or $integrityRid -ge [uint32]0x3000 -or $isSystem) {
            throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: module admission requires a non-elevated, non-system process token below high integrity'
        }
        return [PSCustomObject][ordered]@{ is_elevated = $false; integrity_rid = [Int64]$integrityRid; is_system = $false; thread_impersonating = $false }
    }
    catch {
        if ([string]$_.Exception.Message -like 'POWERSHELL_MODULE_AUTHORITY_BLOCKED:*') { throw }
        throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: cannot validate the current process token: $($_.Exception.Message)"
    }
    finally {
        if ([IntPtr]::Zero -ne $returnLength) { [Runtime.InteropServices.Marshal]::FreeHGlobal($returnLength) }
        if ([IntPtr]::Zero -ne $integrityBuffer) { [Runtime.InteropServices.Marshal]::FreeHGlobal($integrityBuffer) }
        if ([IntPtr]::Zero -ne $elevationBuffer) { [Runtime.InteropServices.Marshal]::FreeHGlobal($elevationBuffer) }
        if ($null -ne $threadIdentity) { $threadIdentity.Dispose() }
        if ($null -ne $processIdentity) { $processIdentity.Dispose() }
    }
}

function Test-D32PowerShellAuthorityTokenRecord {
    param([AllowNull()][object]$Token)
    if ($null -eq $Token -or $Token -is [string] -or $Token -is [Array] -or $Token -is [ValueType]) { return $false }
    $fields = [System.Collections.Generic.List[string]]::new()
    if ($Token -is [System.Collections.IDictionary]) { foreach ($key in $Token.Keys) { $fields.Add([string]$key) } }
    else { foreach ($property in $Token.PSObject.Properties) { $fields.Add([string]$property.Name) } }
    if ($fields.Count -ne 4) { return $false }
    foreach ($field in @('is_elevated','integrity_rid','is_system','thread_impersonating')) { if (-not $fields.Contains($field)) { return $false } }
    $get = { param($object, $name) if ($object -is [System.Collections.IDictionary]) { return $object[$name] } return $object.PSObject.Properties[$name].Value }
    $isElevated = & $get $Token 'is_elevated'; $integrityRid = & $get $Token 'integrity_rid'; $isSystem = & $get $Token 'is_system'; $isImpersonating = & $get $Token 'thread_impersonating'
    if ($isElevated -isnot [bool] -or $isElevated -or $isSystem -isnot [bool] -or $isSystem -or $isImpersonating -isnot [bool] -or $isImpersonating -or
        -not ($integrityRid -is [int32] -or $integrityRid -is [int64] -or $integrityRid -is [uint32] -or $integrityRid -is [uint64]) -or
        [Int64]$integrityRid -lt 0x1000 -or [Int64]$integrityRid -ge 0x3000) { return $false }
    return $true
}

function Get-D32PowerShellModuleAdmissionField {
    param(
        [Parameter(Mandatory = $true)][object]$Record,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if ($Record -is [System.Collections.IDictionary]) { $value = $Record[$Name] }
    else {
        $property = $Record.PSObject.Properties[$Name]
        if ($null -eq $property) { return $null }
        $value = $property.Value
    }
    # Keep an empty or singleton array as an array across the PowerShell
    # function-output pipeline. This is required for strict record shapes such
    # as active_environment=[], where ordinary `return $value` emits no object.
    if ($value -is [Array]) { return ,$value }
    return $value
}

function Get-D32PowerShellAuthorityHandleIdentity {
    param([Parameter(Mandatory = $true)][Microsoft.Win32.SafeHandles.SafeFileHandle]$Handle)
    Initialize-D32PowerShellAuthorityNativeApi
    $buffer = [Runtime.InteropServices.Marshal]::AllocHGlobal(52)
    $fileIdInfo = [Runtime.InteropServices.Marshal]::AllocHGlobal(24)
    try {
        if (-not [D32PowerShellModuleNativeV2]::GetFileInformationByHandle($Handle, $buffer)) {
            throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: native opened-handle identity is unavailable'
        }
        $attributes = [Runtime.InteropServices.Marshal]::ReadInt32($buffer, 0)
        if (-not [D32PowerShellModuleNativeV2]::GetFileInformationByHandleEx($Handle, 18, $fileIdInfo, 24)) {
            throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: 128-bit opened-handle file identity is unavailable'
        }
        $volume = [BitConverter]::ToUInt64([BitConverter]::GetBytes([Runtime.InteropServices.Marshal]::ReadInt64($fileIdInfo, 0)), 0).ToString('x16', [Globalization.CultureInfo]::InvariantCulture)
        $idBytes = [byte[]]::new(16)
        [Runtime.InteropServices.Marshal]::Copy([IntPtr]::Add($fileIdInfo, 8), $idBytes, 0, $idBytes.Length)
        $fileId = [BitConverter]::ToString($idBytes).Replace('-', '').ToLowerInvariant()
        $sizeHigh = [uint32][Runtime.InteropServices.Marshal]::ReadInt32($buffer, 32)
        $sizeLow = [uint32][Runtime.InteropServices.Marshal]::ReadInt32($buffer, 36)
        $bytes = ([Int64]$sizeHigh * 4294967296L) + [Int64]$sizeLow
        return [PSCustomObject]@{ Attributes = $attributes; VolumeSerialHex = $volume; FileIdHex = $fileId; Bytes = $bytes }
    }
    finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($fileIdInfo)
        [Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
    }
}

function Get-D32PowerShellAuthorityFinalHandlePath {
    param([Parameter(Mandatory = $true)][Microsoft.Win32.SafeHandles.SafeFileHandle]$Handle)
    Initialize-D32PowerShellAuthorityNativeApi
    $buffer = [Text.StringBuilder]::new(32768)
    $length = [D32PowerShellModuleNativeV2]::GetFinalPathNameByHandleW($Handle, $buffer, [uint32]$buffer.Capacity, 0)
    if ($length -le 0 -or $length -ge $buffer.Capacity) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: final opened-handle path is unavailable or exceeds the bound' }
    $path = [string]$buffer.ToString()
    if ($path.StartsWith('\\?\UNC\', [StringComparison]::OrdinalIgnoreCase)) { $path = '\\' + $path.Substring(8) }
    elseif ($path.StartsWith('\\?\', [StringComparison]::OrdinalIgnoreCase)) { $path = $path.Substring(4) }
    return [IO.Path]::GetFullPath($path)
}

function Get-D32PowerShellAuthorityObjectSecurity {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][bool]$IsDirectory,
        [AllowNull()][Microsoft.Win32.SafeHandles.SafeFileHandle]$Handle,
        [AllowNull()][IO.FileStream]$Stream
    )
    try {
        if ($IsDirectory) {
            $security = [IO.FileSystemAclExtensions]::GetAccessControl([IO.DirectoryInfo]::new($Path))
        }
        else {
            if ($null -eq $Handle -or $Handle.IsClosed -or $Handle.IsInvalid -or $null -eq $Stream -or -not [object]::ReferenceEquals($Stream.SafeFileHandle, $Handle)) { throw 'missing matching opened file stream for ACL read' }
            $security = [IO.FileSystemAclExtensions]::GetAccessControl($Stream)
        }
        $ownerSid = [string]$security.GetOwner([Security.Principal.SecurityIdentifier]).Value
        $sddl = [string]$security.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group -bor [Security.AccessControl.AccessControlSections]::Access)
        $aclHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes($sddl))).ToLowerInvariant()
        return [PSCustomObject]@{ Path = [IO.Path]::GetFullPath($Path); OwnerSid = $ownerSid; Sddl = $sddl; AclSha256 = $aclHash; Security = $security }
    }
    catch { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: cannot read security descriptor for opened object $Path : $($_.Exception.Message)" }
}

function Test-D32PowerShellAuthorityProtectedSecurity {
    param(
        [Parameter(Mandatory = $true)][object]$Security,
        [Parameter(Mandatory = $true)][bool]$IsDirectory,
        [switch]$IsProtectedAncestor,
        [switch]$IsProgramDataAncestor,
        [AllowEmptyString()][string]$PowerShellRoot = ''
    )
    $trustedWriterSids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($sid in @('S-1-5-18','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464','S-1-5-32-544')) { [void]$trustedWriterSids.Add($sid) }
    try {
        $rawSecurityDescriptor = [Security.AccessControl.RawSecurityDescriptor]::new([byte[]]$Security.Security.GetSecurityDescriptorBinaryForm(), 0)
        if ($null -eq $rawSecurityDescriptor.DiscretionaryAcl -or
            ($rawSecurityDescriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -eq 0) { return $false }
    }
    catch { return $false }
    if (-not $trustedWriterSids.Contains([string]$Security.OwnerSid)) { return $false }
    $securityPath = ''
    $pathProperty = $Security.PSObject.Properties['Path']
    if ($null -ne $pathProperty) { $securityPath = [string]$pathProperty.Value }
    $isExactProgramData = [StringComparer]::OrdinalIgnoreCase.Equals($securityPath, 'C:\ProgramData')
    $volumeRoot = ''
    $powerShellRoot = ''
    try {
        $securityRoot = if (-not [string]::IsNullOrWhiteSpace($PowerShellRoot)) { $PowerShellRoot }
            else { Get-D32PowerShellAuthorityTrustedRuntimeRoot }
        $powerShellRoot = [IO.Path]::GetFullPath([string]$securityRoot)
        $volumeRoot = [IO.Path]::GetPathRoot($powerShellRoot)
    }
    catch { return $false }
    $isLocalVolumeRoot = $volumeRoot -cmatch '^[A-Za-z]:\\$'
    $isExactVolumeRootAncestor = $IsProtectedAncestor -and $isLocalVolumeRoot -and
        [StringComparer]::OrdinalIgnoreCase.Equals($securityPath, $volumeRoot) -and
        (Test-D32PowerShellAuthorityPathWithin -Child $powerShellRoot -Parent $securityPath) -and
        -not [StringComparer]::OrdinalIgnoreCase.Equals($powerShellRoot, $securityPath) -and
        [string]$Security.OwnerSid -ceq 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' -and
        $IsDirectory -and $Security.Security.AreAccessRulesProtected
    if ($isExactProgramData -and (-not $IsDirectory -or [string]$Security.OwnerSid -cne 'S-1-5-18')) { return $false }
    if ([StringComparer]::OrdinalIgnoreCase.Equals($securityPath, 'C:\ProgramData\Microsoft') -and
        (-not $IsDirectory -or [string]$Security.OwnerSid -cne 'S-1-5-18' -or -not $Security.Security.AreAccessRulesProtected)) { return $false }
    $writeMask = [int64]0x00000002 -bor [int64]0x00000004 -bor [int64]0x00000010 -bor [int64]0x00000040 -bor
        [int64]0x00000100 -bor [int64]0x00010000 -bor [int64]0x00040000 -bor [int64]0x00080000 -bor
        [int64]0x01000000 -bor [int64]0x10000000 -bor [int64]0x40000000
    # ProgramData is a known Windows ancestor used by Defender's platform
    # directory. Its stock Everyone ACE permits metadata changes and creation
    # of unrelated children, but not deleting/replacing a child, changing its
    # ACL/owner, or writing the existing Microsoft child. Permit only those
    # exact non-redirecting bits here; all other ProgramData write rights fail.
    # The exception is deliberately exact: it cannot be applied to arbitrary
    # ancestors such as C:\Windows, and only a SYSTEM-owned ProgramData
    # directory qualifies.
    $programDataSafeAdditions = [int64]0x00000002 -bor [int64]0x00000004 -bor [int64]0x00000010 -bor [int64]0x00000100
    # The exact local volume root is a non-resolver ancestor, not a resolver
    # directory. Only an untrusted directory-child creation right (0x4) is
    # tolerated there after its opened identity, owner and protected descriptor
    # are recorded in the independently pinned full-distribution ancestor
    # inventory. Absolute PSHOME/System32 roots and the finite admitted resolver
    # inputs keep a newly created root sibling outside the resolver domain.
    # Never extend this to PSHOME itself, another drive/UNC/nested ancestor, or
    # any file-creation, metadata, delete/rename/reparse, DACL/owner right.
    $volumeRootSafeAdditions = [int64]0x00000004
    if ($IsProgramDataAncestor) {
        if (-not $isExactProgramData) { return $false }
        $writeMask = $writeMask -band (-bnot $programDataSafeAdditions)
    }
    elseif ($isExactVolumeRootAncestor) { $writeMask = $writeMask -band (-bnot $volumeRootSafeAdditions) }
    elseif ($isExactProgramData) { return $false }
    foreach ($rule in $Security.Security.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
        $sid = [string]$rule.IdentityReference.Value
        if ($trustedWriterSids.Contains($sid)) { continue }
        $mask = [int64]$rule.FileSystemRights
        $untrustedWrite = $mask -band $writeMask
        if ($IsProgramDataAncestor) {
            if (($untrustedWrite -band (-bnot $programDataSafeAdditions)) -ne 0) { return $false }
        }
        elseif ($isExactVolumeRootAncestor) {
            if (($untrustedWrite -band (-bnot $volumeRootSafeAdditions)) -ne 0) { return $false }
        }
        elseif ($untrustedWrite -ne 0) { return $false }
    }
    return $true
}

function Get-D32PowerShellAuthoritySecurityRecord {
    param([Parameter(Mandatory = $true)][object]$Security)
    if (-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $Security -IsDirectory:$false)) {
        throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: object owner or ACL grants an untrusted trustee namespace write/replace/delete/reparse/DACL/owner rights'
    }
    return [ordered]@{ owner_sid = [string]$Security.OwnerSid; security_descriptor_sddl = [string]$Security.Sddl; security_descriptor_sha256 = [string]$Security.AclSha256 }
}

function Open-D32PowerShellAuthorityDirectoryFence {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    if ($null -ne $script:D32PowerShellAuthorityTestProvider -and $null -ne $script:D32PowerShellAuthorityTestProvider.OpenDirectory) {
        return & $script:D32PowerShellAuthorityTestProvider.OpenDirectory -Path $full
    }
    Initialize-D32PowerShellAuthorityNativeApi
    # V2 handles witness object identity only. Protected namespace policy, not a
    # directory share-mode lock, proves that untrusted writers cannot redirect it.
    $handle = [D32PowerShellModuleNativeV2]::CreateFileW($full, 0x80, 0x07, [IntPtr]::Zero, 3, 0x02000000 -bor 0x00200000, [IntPtr]::Zero)
    if ($null -eq $handle -or $handle.IsInvalid) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: cannot hold stable directory fence: $full" }
    try {
        $identity = Get-D32PowerShellAuthorityHandleIdentity -Handle $handle
        $finalPath = Get-D32PowerShellAuthorityFinalHandlePath -Handle $handle
        if (($identity.Attributes -band [int][IO.FileAttributes]::Directory) -eq 0 -or
            ($identity.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals($finalPath, $full)) {
            throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: directory is not a regular non-reparse object: $full"
        }
        $security = Get-D32PowerShellAuthorityObjectSecurity -Path $full -IsDirectory:$true -Handle $handle
        $securityRoot = Get-D32PowerShellAuthorityTrustedRuntimeRoot
        $runtimeDirectory = Test-D32PowerShellAuthorityPathWithin -Child $full -Parent $securityRoot
        $runtimeAncestor = -not $runtimeDirectory -and (Test-D32PowerShellAuthorityPathWithin -Child $securityRoot -Parent $full)
        if (($runtimeDirectory -or $runtimeAncestor) -and -not (Test-D32PowerShellAuthorityProtectedSecurity -Security $security -IsDirectory:$true -IsProtectedAncestor:$runtimeAncestor -PowerShellRoot $securityRoot)) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: untrusted namespace writer on PowerShell runtime directory/ancestor: $full" }
        $afterSecurity = Get-D32PowerShellAuthorityHandleIdentity -Handle $handle
        if ($afterSecurity.VolumeSerialHex -cne $identity.VolumeSerialHex -or $afterSecurity.FileIdHex -cne $identity.FileIdHex -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals((Get-D32PowerShellAuthorityFinalHandlePath -Handle $handle), $full)) {
            throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: directory object changed during ACL validation: $full"
        }
        return [PSCustomObject]@{ Path = $full; VolumeSerialHex = $identity.VolumeSerialHex; FileIdHex = $identity.FileIdHex; OwnerSid = $security.OwnerSid; Sddl = $security.Sddl; AclSha256 = $security.AclSha256; Security = $security.Security; Handle = $handle }
    }
    catch { $handle.Dispose(); throw }
}

function Add-D32PowerShellAuthorityDirectoryChain {
    param([Parameter(Mandatory = $true)][string]$Directory, [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Fences)
    $full = [IO.Path]::GetFullPath($Directory).TrimEnd([char[]]@('\', '/'))
    $root = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($Directory))
    if ([String]::IsNullOrWhiteSpace($root)) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: directory path has no root' }
    $chain = [System.Collections.Generic.List[string]]::new()
    $current = $root
    $chain.Add($current)
    $remainder = [IO.Path]::GetFullPath($Directory).Substring($root.Length)
    foreach ($part in @($remainder -split '[\\/]+' )) {
        Assert-D32PowerShellAuthorityPreparationDeadline
        if ([String]::IsNullOrWhiteSpace($part)) { continue }
        $current = [IO.Path]::Combine($current, $part)
        $chain.Add($current)
    }
    foreach ($item in $chain) {
        Assert-D32PowerShellAuthorityPreparationDeadline
        $key = [IO.Path]::GetFullPath($item).TrimEnd([char[]]@('\', '/'))
        if ($key.Length -eq 2 -and $key[1] -eq ':') { $key += [IO.Path]::DirectorySeparatorChar }
        if (-not $Fences.Contains($key)) { $Fences[$key] = Open-D32PowerShellAuthorityDirectoryFence -Path $key }
    }
}

function Open-D32PowerShellAuthorityFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$DirectoryFences,
        [ValidateRange(1, 2147483647)][Int64]$MaximumBytes = [Int32]::MaxValue,
        [long]$DeadlineTicks = 0
    )
    if ($null -ne $script:D32PowerShellAuthorityTestProvider -and $null -ne $script:D32PowerShellAuthorityTestProvider.OpenFile) {
        return & $script:D32PowerShellAuthorityTestProvider.OpenFile -Path $Path -DirectoryFences $DirectoryFences `
            -MaximumBytes $MaximumBytes -DeadlineTicks $DeadlineTicks
    }
    if ($DeadlineTicks -le 0 -and [long]$script:D32PowerShellAuthorityPreparationDeadlineTicks -gt 0) { $DeadlineTicks = [long]$script:D32PowerShellAuthorityPreparationDeadlineTicks }
    if ($DeadlineTicks -gt 0 -and [Diagnostics.Stopwatch]::GetTimestamp() -ge $DeadlineTicks) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: shared source-proof work deadline reached before bounded file open' }
    $full = [IO.Path]::GetFullPath($Path)
    if (-not (Test-D32PowerShellAuthorityPathNoReparse -Path $full)) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: missing or reparse-backed file: $full" }
    Add-D32PowerShellAuthorityDirectoryChain -Directory ([IO.Path]::GetDirectoryName($full)) -Fences $DirectoryFences
    if ($DeadlineTicks -gt 0 -and [Diagnostics.Stopwatch]::GetTimestamp() -ge $DeadlineTicks) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: shared source-proof work deadline reached before bounded file open' }
    # File handles witness opened content/object identity; they are not locks or
    # namespace-freeze evidence. Keep normal OS/runtime servicing compatible.
    # Protected ACLs and the no-maintenance-during-run premise provide exclusion.
    $share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
    $stream = [IO.FileStream]::new($full, [IO.FileMode]::Open, [IO.FileAccess]::Read, $share)
    try {
        $before = Get-D32PowerShellAuthorityHandleIdentity -Handle $stream.SafeFileHandle
        $finalPath = Get-D32PowerShellAuthorityFinalHandlePath -Handle $stream.SafeFileHandle
        if (($before.Attributes -band [int][IO.FileAttributes]::Directory) -ne 0 -or
            ($before.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0 -or $before.Bytes -le 0 -or $before.Bytes -gt $MaximumBytes -or $before.Bytes -gt [Int32]::MaxValue -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals($finalPath, $full)) {
            throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: expected bounded regular opened file: $full"
        }
        $bytes = [byte[]]::new([int]$before.Bytes)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            if ($DeadlineTicks -gt 0 -and [Diagnostics.Stopwatch]::GetTimestamp() -ge $DeadlineTicks) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: shared source-proof work deadline reached before bounded file read' }
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: file changed during opened read: $full" }
            if ($DeadlineTicks -gt 0 -and [Diagnostics.Stopwatch]::GetTimestamp() -ge $DeadlineTicks) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: late bounded file-read bytes discarded at the shared source-proof work deadline' }
            $offset += $read
        }
        if ($DeadlineTicks -gt 0 -and [Diagnostics.Stopwatch]::GetTimestamp() -ge $DeadlineTicks) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: late bounded file-read bytes discarded before source-proof hashing' }
        $after = Get-D32PowerShellAuthorityHandleIdentity -Handle $stream.SafeFileHandle
        $security = Get-D32PowerShellAuthorityObjectSecurity -Path $full -IsDirectory:$false -Handle $stream.SafeFileHandle -Stream $stream
        $securityRoot = Get-D32PowerShellAuthorityTrustedRuntimeRoot
        if ((Test-D32PowerShellAuthorityPathWithin -Child $full -Parent $securityRoot) -and
            -not (Test-D32PowerShellAuthorityProtectedSecurity -Security $security -IsDirectory:$false -PowerShellRoot $securityRoot)) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: untrusted namespace writer on PowerShell runtime file: $full" }
        if ($stream.Length -ne $before.Bytes -or $after.Bytes -ne $before.Bytes -or
            $before.VolumeSerialHex -cne $after.VolumeSerialHex -or $before.FileIdHex -cne $after.FileIdHex -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath($full), [IO.Path]::GetFullPath($stream.Name)) -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals((Get-D32PowerShellAuthorityFinalHandlePath -Handle $stream.SafeFileHandle), $full)) {
            throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: opened file identity changed while reading: $full"
        }
        if ($DeadlineTicks -gt 0 -and [Diagnostics.Stopwatch]::GetTimestamp() -ge $DeadlineTicks) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: late bounded file-read bytes discarded before source-proof hashing' }
        $sha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
        return [PSCustomObject]@{
            Record = [ordered]@{ path = $full; bytes = [Int64]$before.Bytes; sha256 = $sha; volume_serial_hex = $before.VolumeSerialHex; file_id_hex = $before.FileIdHex }
            Security = $security
            Stream = $stream; Bytes = $bytes
        }
    }
    catch { $stream.Dispose(); throw }
}

function Test-D32PowerShellAuthorityJsonDuplicates {
    param([System.Text.Json.JsonElement]$Element)
    switch ($Element.ValueKind) {
        ([System.Text.Json.JsonValueKind]::Object) {
            $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($property in $Element.EnumerateObject()) {
                if (-not $seen.Add($property.Name) -or (Test-D32PowerShellAuthorityJsonDuplicates -Element $property.Value)) { return $true }
            }
        }
        ([System.Text.Json.JsonValueKind]::Array) {
            foreach ($item in $Element.EnumerateArray()) { if (Test-D32PowerShellAuthorityJsonDuplicates -Element $item) { return $true } }
        }
    }
    return $false
}

function ConvertFrom-D32PowerShellAuthorityJsonElement {
    param([Parameter(Mandatory = $true)][System.Text.Json.JsonElement]$Element)
    switch ($Element.ValueKind) {
        ([System.Text.Json.JsonValueKind]::Object) {
            $properties = [ordered]@{}
            foreach ($property in $Element.EnumerateObject()) { $properties.Add($property.Name, (ConvertFrom-D32PowerShellAuthorityJsonElement -Element $property.Value)) }
            return [PSCustomObject]$properties
        }
        ([System.Text.Json.JsonValueKind]::Array) {
            $items = [System.Collections.Generic.List[object]]::new()
            foreach ($item in $Element.EnumerateArray()) { $items.Add((ConvertFrom-D32PowerShellAuthorityJsonElement -Element $item)) }
            return ,$items.ToArray()
        }
        ([System.Text.Json.JsonValueKind]::String) { return $Element.GetString() }
        ([System.Text.Json.JsonValueKind]::Number) {
            $number = [Int64]0
            if (-not $Element.TryGetInt64([ref]$number)) { throw 'FACTS_REQUEST_BLOCKED: JSON numbers must be signed 64-bit integers' }
            return $number
        }
        ([System.Text.Json.JsonValueKind]::True) { return $true }
        ([System.Text.Json.JsonValueKind]::False) { return $false }
        ([System.Text.Json.JsonValueKind]::Null) { return $null }
        default { throw 'FACTS_REQUEST_BLOCKED: JSON contains an unsupported token' }
    }
}

function Read-D32PowerShellAuthorityFactsRequest {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedRecordType,
        [Parameter(Mandatory = $true)][string[]]$RequiredFields,
        [string[]]$OptionalFields = @(),
        [ValidateRange(1024, 1048576)][int]$MaximumBytes = 65536
    )
    if (-not [IO.Path]::IsPathRooted($Path) -or [IO.Path]::GetFullPath($Path) -cne $Path) { throw 'FACTS_REQUEST_BLOCKED: input path must be literal, canonical, and absolute' }
    $directoryFences = [System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)
    $opened = $null
    try {
        $opened = Open-D32PowerShellAuthorityFile -Path $Path -DirectoryFences $directoryFences -MaximumBytes $MaximumBytes
        $jsonText = [Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$opened.Bytes)
        $document = [System.Text.Json.JsonDocument]::Parse($jsonText, [System.Text.Json.JsonDocumentOptions]@{ MaxDepth = 24; CommentHandling = [System.Text.Json.JsonCommentHandling]::Disallow; AllowTrailingCommas = $false })
        try {
            $element = $document.RootElement
            if ($element.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or (Test-D32PowerShellAuthorityJsonDuplicates -Element $element)) {
                throw 'FACTS_REQUEST_BLOCKED: input must be a duplicate-free JSON object'
            }
            $expected = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($field in $RequiredFields) { if (-not $expected.Add([string]$field)) { throw 'FACTS_REQUEST_BLOCKED: internal required field list has duplicates' } }
            foreach ($field in $OptionalFields) { if (-not $expected.Add([string]$field)) { throw 'FACTS_REQUEST_BLOCKED: internal optional field list overlaps or has duplicates' } }
            $actual = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($property in $element.EnumerateObject()) {
                if (-not $actual.Add($property.Name) -or -not $expected.Contains($property.Name)) { throw "FACTS_REQUEST_BLOCKED: input has duplicate or extra field '$($property.Name)'" }
            }
            foreach ($field in $RequiredFields) { if (-not $actual.Contains([string]$field)) { throw "FACTS_REQUEST_BLOCKED: input is missing required field '$field'" } }
            if ($element.GetProperty('record_type').ValueKind -ne [System.Text.Json.JsonValueKind]::String -or $element.GetProperty('record_type').GetString() -cne $ExpectedRecordType -or
                $element.GetProperty('schema_version').ValueKind -ne [System.Text.Json.JsonValueKind]::Number -or $element.GetProperty('schema_version').GetRawText() -cne '1') {
                throw 'FACTS_REQUEST_BLOCKED: input record type or version is unsupported'
            }
            return ConvertFrom-D32PowerShellAuthorityJsonElement -Element $element
        }
        finally { $document.Dispose() }
    }
    catch {
        if ([string]$_.Exception.Message -like 'FACTS_REQUEST_BLOCKED:*') { throw }
        throw "FACTS_REQUEST_BLOCKED: $($_.Exception.Message)"
    }
    finally {
        if ($null -ne $opened -and $null -ne $opened.Stream) { $opened.Stream.Dispose() }
        foreach ($fence in $directoryFences.Values) { if ($null -ne $fence.Handle -and -not $fence.Handle.IsClosed) { $fence.Handle.Dispose() } }
    }
}

function Get-D32PowerShellAuthorityLoadedModuleSet {
    $identities = [System.Collections.Generic.List[string]]::new()
    foreach ($module in (Microsoft.PowerShell.Core\Get-Module)) {
        $path = if ([String]::IsNullOrWhiteSpace([string]$module.Path)) { '<in-memory>' } else { [IO.Path]::GetFullPath([string]$module.Path) }
        $identities.Add(([string]$module.Name + '|' + $path))
    }
    $identities.Sort([StringComparer]::OrdinalIgnoreCase)
    return ,$identities.ToArray()
}

function Assert-D32PowerShellAuthorityLoadedModuleSetUnchanged {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Expected)
    $actual = Get-D32PowerShellAuthorityLoadedModuleSet
    if ($actual.Count -ne $Expected.Count) { throw 'FACTS_PREPARATION_BLOCKED: module-free facts preparation changed the loaded module set' }
    for ($index = 0; $index -lt $actual.Count; $index++) {
        if (-not [StringComparer]::OrdinalIgnoreCase.Equals($actual[$index], $Expected[$index])) { throw 'FACTS_PREPARATION_BLOCKED: module-free facts preparation changed the loaded module set' }
    }
}

function Test-D32PowerShellAuthorityJsonFields {
    param([System.Text.Json.JsonElement]$Element, [string[]]$Expected)
    if ($Element.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { return $false }
    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($property in $Element.EnumerateObject()) { $names.Add($property.Name) }
    if ($names.Count -ne $Expected.Count) { return $false }
    foreach ($name in $Expected) { if (-not $names.Contains($name)) { return $false } }
    return $true
}

function Get-D32PowerShellAuthorityManifestData {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes, [Parameter(Mandatory = $true)][string]$ModuleName)
    $text = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: invalid literal module manifest: $ModuleName" }
    $tables = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.HashtableAst] }, $true))
    if ($tables.Count -lt 1) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: module manifest is not a literal data file: $ModuleName" }
    $table = $tables[0]
    $keys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($pair in $table.KeyValuePairs) {
        $key = $null
        try { $key = [string]$pair.Item1.SafeGetValue() } catch { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: dynamic module manifest key: $ModuleName" }
        if (-not $keys.Add($key)) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: duplicate module manifest field: $ModuleName/$key" }
    }
    try { $data = $table.SafeGetValue() } catch { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: executable module manifest expression: $ModuleName" }
    if ($data -isnot [System.Collections.IDictionary]) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: module manifest root must be a literal hashtable: $ModuleName" }
    if ($data.Contains('ModuleToProcess')) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: module manifest alias ModuleToProcess is not accepted: $ModuleName" }
    if ($data.Contains('Prefix') -and -not [String]::IsNullOrEmpty([string]$data['Prefix'])) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: manifest prefix is not accepted: $ModuleName" }
    $root = if ($data.Contains('RootModule')) { [string]$data['RootModule'] } else { '' }
    $nested = @(); if ($data.Contains('NestedModules')) { $nested = @($data['NestedModules']) }
    $required = @(); if ($data.Contains('RequiredModules')) { $required = @($data['RequiredModules']) }
    $scripts = @(); if ($data.Contains('ScriptsToProcess')) { $scripts = @($data['ScriptsToProcess']) }
    $assemblies = @(); if ($data.Contains('RequiredAssemblies')) { $assemblies = @($data['RequiredAssemblies']) }
    $types = @(); if ($data.Contains('TypesToProcess')) { $types = @($data['TypesToProcess']) }
    $formats = @(); if ($data.Contains('FormatsToProcess')) { $formats = @($data['FormatsToProcess']) }
    $moduleList = @(); if ($data.Contains('ModuleListToProcess')) { $moduleList = @($data['ModuleListToProcess']) }
    foreach ($value in @($nested) + @($required) + @($scripts) + @($assemblies) + @($types) + @($formats) + @($moduleList)) {
        if ($value -isnot [string] -or [String]::IsNullOrWhiteSpace([string]$value) -or $value.Contains('*') -or $value.Contains('?') -or [IO.Path]::IsPathRooted([string]$value)) {
            throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: module manifest contains a non-literal or wildcard resolution: $ModuleName"
        }
    }
    if (-not [String]::IsNullOrEmpty($root) -and ($root.Contains('*') -or $root.Contains('?') -or [IO.Path]::IsPathRooted($root))) {
        throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: module manifest root module is not a relative exact name: $ModuleName"
    }
    return [PSCustomObject]@{ RootModule = $root; NestedModules = [string[]]$nested; RequiredModules = [object[]]$required; ScriptsToProcess = [string[]]$scripts; RequiredAssemblies = [string[]]$assemblies; TypesToProcess = [string[]]$types; FormatsToProcess = [string[]]$formats; ModuleListToProcess = [string[]]$moduleList }
}

function Get-D32PowerShellAuthorityFixedModuleRoles {
    param([Parameter(Mandatory = $true)][string]$PowerShellRoot)
    $moduleRoot = [IO.Path]::GetFullPath([IO.Path]::Combine($PowerShellRoot, 'Modules'))
    return @(
        [PSCustomObject]@{ Role = 'Management'; Name = 'Microsoft.PowerShell.Management'; Manifest = [IO.Path]::Combine($moduleRoot, 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Management.psd1'); Nested = @('Microsoft.PowerShell.Commands.Management.dll'); Root = ''; Assemblies = @(); Extra = @() },
        [PSCustomObject]@{ Role = 'Utility'; Name = 'Microsoft.PowerShell.Utility'; Manifest = [IO.Path]::Combine($moduleRoot, 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Utility.psd1'); Nested = @('Microsoft.PowerShell.Commands.Utility.dll'); Root = ''; Assemblies = @(); Extra = @() },
        [PSCustomObject]@{ Role = 'CimCmdlets'; Name = 'CimCmdlets'; Manifest = [IO.Path]::Combine($moduleRoot, 'CimCmdlets', 'CimCmdlets.psd1'); Nested = @(); Root = 'Microsoft.Management.Infrastructure.CimCmdlets'; Assemblies = @('Microsoft.Management.Infrastructure.CimCmdlets.dll', 'Microsoft.Management.Infrastructure.Dll'); Extra = @('microsoft.management.infrastructure.native.dll', 'microsoft.management.infrastructure.native.unmanaged.dll') }
    )
}

function Get-D32PowerShellAuthorityFixedImportAssemblyPaths {
    param([Parameter(Mandatory = $true)][string]$PowerShellRoot)
    $paths = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($role in (Get-D32PowerShellAuthorityFixedModuleRoles -PowerShellRoot $PowerShellRoot)) {
        $names = @($role.Nested) + @($role.Assemblies)
        if (-not [String]::IsNullOrWhiteSpace([string]$role.Root)) { $names += ([string]$role.Root + '.dll') }
        foreach ($name in $names) {
            $path = [IO.Path]::GetFullPath([IO.Path]::Combine($PowerShellRoot, [string]$name))
            if (-not $seen.Add($path)) { continue }
            $paths.Add($path)
        }
    }
    return [string[]]$paths.ToArray()
}

function Get-D32PowerShellAuthorityFixedModuleClosureRootPaths {
    param([Parameter(Mandatory = $true)][string]$PowerShellRoot, [Parameter(Mandatory = $true)][string]$ModuleName)
    $role = $null
    foreach ($candidate in (Get-D32PowerShellAuthorityFixedModuleRoles -PowerShellRoot $PowerShellRoot)) {
        if ([string]$candidate.Name -ceq $ModuleName) { $role = $candidate; break }
    }
    if ($null -eq $role) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: unknown fixed module role for closure paths: $ModuleName" }

    # These are only exact PSHOME-root content paths admitted by this role's
    # frozen manifest relationships. Extra contains fixed non-assembly runtime
    # dependencies that are part of the module content closure, but are not
    # import assemblies and must not enter the resolver assembly allowlist.
    $names = @($role.Nested) + @($role.Assemblies) + @($role.Extra)
    if (-not [String]::IsNullOrWhiteSpace([string]$role.Root)) { $names += ([string]$role.Root + '.dll') }
    $paths = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $names) {
        $path = [IO.Path]::GetFullPath([IO.Path]::Combine($PowerShellRoot, [string]$name))
        if ($seen.Add($path)) { $paths.Add($path) }
    }
    return [string[]]$paths.ToArray()
}

function Get-D32PowerShellAuthorityAllowedModulePaths {
    param([Parameter(Mandatory = $true)][string]$PowerShellRoot, [Parameter(Mandatory = $true)][object]$Role)
    $paths = [System.Collections.Generic.List[string]]::new()
    $paths.Add([IO.Path]::GetFullPath([string]$Role.Manifest))
    if (-not [String]::IsNullOrWhiteSpace([string]$Role.Root)) { $paths.Add([IO.Path]::GetFullPath([IO.Path]::Combine($PowerShellRoot, ([string]$Role.Root + '.dll')))) }
    foreach ($nested in $Role.Nested) { $paths.Add([IO.Path]::GetFullPath([IO.Path]::Combine($PowerShellRoot, [string]$nested))) }
    return [string[]]$paths.ToArray()
}

function Get-D32PowerShellAuthorityModuleTreePaths {
    param([Parameter(Mandatory = $true)][string]$ModuleDirectory)
    $paths = [System.Collections.Generic.List[string]]::new()
    $pending = [System.Collections.Generic.Stack[string]]::new()
    $pending.Push([IO.Path]::GetFullPath($ModuleDirectory))
    $visitedDirectories = 0
    while ($pending.Count -gt 0) {
        Assert-D32PowerShellAuthorityPreparationDeadline
        if (++$visitedDirectories -gt 1024) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: bounded fixed-module directory count exceeded' }
        $directory = $pending.Pop()
        Add-D32PowerShellAuthorityDirectoryChain -Directory $directory -Fences $script:D32PowerShellAdmissionDirectoryFences
        if (-not (Test-D32PowerShellAuthorityPathNoReparse -Path $directory)) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: module directory tree contains a reparse path: $directory" }
        foreach ($file in [IO.Directory]::GetFiles($directory)) {
            Assert-D32PowerShellAuthorityPreparationDeadline
            if ($paths.Count -ge 4096) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: bounded fixed-module file count exceeded' }
            $paths.Add([IO.Path]::GetFullPath($file))
        }
        foreach ($child in [IO.Directory]::GetDirectories($directory)) {
            Assert-D32PowerShellAuthorityPreparationDeadline
            $attributes = [IO.File]::GetAttributes($child)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: module directory tree contains a reparse directory: $child" }
            $pending.Push([IO.Path]::GetFullPath($child))
        }
    }
    return [string[]]$paths.ToArray()
}

function Get-D32PowerShellAuthorityExpectedModuleFiles {
    param([Parameter(Mandatory = $true)][string]$PowerShellRoot, [Parameter(Mandatory = $true)][object]$Role)
    $moduleDirectory = [IO.Path]::GetDirectoryName([string]$Role.Manifest)
    $manifestSnapshot = Open-D32PowerShellAuthorityFile -Path ([string]$Role.Manifest) -DirectoryFences $script:D32PowerShellAdmissionDirectoryFences
    $semantics = Get-D32PowerShellAuthorityManifestData -Bytes ([byte[]]$manifestSnapshot.Bytes) -ModuleName ([string]$Role.Name)
    if ($semantics.RootModule -cne [string]$Role.Root -or ($semantics.NestedModules -join "`n") -cne ([string[]]$Role.Nested -join "`n") -or
        $semantics.RequiredAssemblies.Count -ne $Role.Assemblies.Count -or ($semantics.RequiredAssemblies -join "`n") -cne ([string[]]$Role.Assemblies -join "`n") -or
        $semantics.RequiredModules.Count -ne 0 -or $semantics.ScriptsToProcess.Count -ne 0 -or $semantics.TypesToProcess.Count -ne 0 -or
        $semantics.FormatsToProcess.Count -ne 0 -or $semantics.ModuleListToProcess.Count -ne 0) {
        $manifestSnapshot.Stream.Dispose()
        throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: fixed role/import relationships changed: $($Role.Name)"
    }
    $paths = [System.Collections.Generic.List[string]]::new()
    $paths.Add([IO.Path]::GetFullPath([string]$Role.Manifest))
    foreach ($file in (Get-D32PowerShellAuthorityModuleTreePaths -ModuleDirectory $moduleDirectory)) { if (-not $paths.Contains([string]$file)) { $paths.Add([string]$file) } }
    $root = [IO.Path]::GetFullPath($PowerShellRoot)
    $rootReferences = @($Role.Nested) + @($Role.Assemblies) + @($Role.Extra)
    if (-not [String]::IsNullOrEmpty([string]$Role.Root)) { $rootReferences += ([string]$Role.Root + '.dll') }
    foreach ($file in $rootReferences) {
        $resolved = [IO.Path]::GetFullPath([IO.Path]::Combine($root, [string]$file))
        if (-not $paths.Contains($resolved)) { $paths.Add($resolved) }
    }
    $unique = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($path in $paths) {
        Assert-D32PowerShellAuthorityPreparationDeadline
        if (-not $unique.Add($path)) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: duplicate module closure path: $path" }
    }
    return [PSCustomObject]@{ Paths = [string[]]$paths; Manifest = $manifestSnapshot; Semantics = $semantics; ModuleDirectory = $moduleDirectory }
}

function Get-D32PowerShellAuthorityInventoryDigest {
    param([Parameter(Mandatory = $true)][string]$Role, [Parameter(Mandatory = $true)][object[]]$Files)
    $builder = [Text.StringBuilder]::new()
    $ordered = [System.Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($file in $Files) {
        $path = [string]$file.path
        if ($ordered.ContainsKey($path)) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: duplicate path in module inventory: $path" }
        $ordered.Add($path, $file)
    }
    foreach ($file in $ordered.Values) {
        $entry = [string]$file.path
        [void]$builder.Append($entry.Length).Append(':').Append($entry).Append('|').Append([Int64]$file.bytes).Append('|').Append([string]$file.sha256).Append('|').Append([string]$file.volume_serial_hex).Append('|').Append([string]$file.file_id_hex).Append("`n")
    }
    $data = [Text.UTF8Encoding]::new($false).GetBytes($Role + "`n" + $builder.ToString())
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($data)).ToLowerInvariant()
}

function Get-D32PowerShellAuthorityRuntimeInventoryDigest {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Directories,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Files,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Ancestors)
    $builder = [Text.StringBuilder]::new()
    $groups = @(
        [PSCustomObject]@{ Kind = 'ancestor'; Items = $Ancestors },
        [PSCustomObject]@{ Kind = 'directory'; Items = $Directories },
        [PSCustomObject]@{ Kind = 'file'; Items = $Files }
    )
    foreach ($group in $groups) {
        $ordered = [System.Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($item in $group.Items) {
            $path = [string]$item.path
            if ($ordered.ContainsKey($path)) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: duplicate path in full runtime distribution: $path" }
            $ordered.Add($path, $item)
        }
        foreach ($item in $ordered.Values) {
            $kind = [string]$item.kind
            if ([string]::IsNullOrWhiteSpace($kind)) { $kind = [string]$group.Kind }
            [void]$builder.Append($kind).Append('|').Append(([string]$item.path).Length).Append(':').Append([string]$item.path).Append('|')
            if ($kind -ceq 'file') { [void]$builder.Append([Int64]$item.bytes).Append('|').Append([string]$item.sha256).Append('|') }
            [void]$builder.Append([string]$item.volume_serial_hex).Append('|').Append([string]$item.file_id_hex).Append('|').Append([string]$item.owner_sid).Append('|').Append([string]$item.security_descriptor_sha256).Append("`n")
        }
    }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($builder.ToString())
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

function Get-D32PowerShellAuthorityOsSecurityInventoryDigest {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Components)
    if ($Components.Count -ne 2) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: OS security inventory must contain exactly the two fixed component roles' }
    $expectedRoles = @('MICROSOFT_WINDOWS_OS_INSTALLATION','MICROSOFT_WINDOWS_DEFENDER_PLATFORM')
    $builder = [Text.StringBuilder]::new()
    for ($index = 0; $index -lt $expectedRoles.Count; $index++) {
        $component = $Components[$index]
        if ($null -eq $component) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: OS security component record is null' }
        $role = [string]$component.component_type
        $digest = [string]$component.inventory_sha256
        if ($role -cne $expectedRoles[$index] -or $digest -cnotmatch '^[0-9a-f]{64}$') {
            throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: OS security component role, order, or inventory digest is invalid'
        }
        [void]$builder.Append($role).Append('|').Append($digest).Append("`n")
    }
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes($builder.ToString()))).ToLowerInvariant()
}

function Assert-D32PowerShellAuthorityPinnedWindowsComponentShape {
    param(
        [Parameter(Mandatory = $true)][System.Text.Json.JsonElement]$Element,
        [Parameter(Mandatory = $true)][string]$ExpectedWindowsRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedSystemRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedOsVersion
    )
    Assert-D32PowerShellAuthorityExactJsonRecord -Element $Element -Fields @('component_type','version','root_path','root_volume_serial_hex','root_file_id_hex','inventory_sha256','source_proof','distribution','native_files') -Name 'pinned Windows OS component'
    $windowsRoot = [IO.Path]::GetFullPath($ExpectedWindowsRoot)
    $systemRoot = [IO.Path]::GetFullPath($ExpectedSystemRoot)
    if ([IO.Path]::GetFullPath($windowsRoot) -cne $windowsRoot -or [IO.Path]::GetFullPath($systemRoot) -cne $systemRoot -or
        (Get-D32PowerShellAuthorityJsonString $Element 'component_type') -cne 'MICROSOFT_WINDOWS_OS_INSTALLATION' -or
        (Get-D32PowerShellAuthorityJsonString $Element 'version') -cne $ExpectedOsVersion -or
        (Get-D32PowerShellAuthorityJsonString $Element 'root_path') -cne $windowsRoot -or
        (Get-D32PowerShellAuthorityJsonString $Element 'root_volume_serial_hex') -cnotmatch '^[0-9a-f]{16}$' -or
        (Get-D32PowerShellAuthorityJsonString $Element 'root_file_id_hex') -cnotmatch '^[0-9a-f]{32}$' -or
        (Get-D32PowerShellAuthorityJsonString $Element 'inventory_sha256') -cnotmatch '^[0-9a-f]{64}$') {
        throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: pinned Windows OS component role, root, version, or identity shape is invalid'
    }
    $proofElement = $Element.GetProperty('source_proof')
    $expectedProof = [ordered]@{
        proof_type = 'GET_WINDOWSDIRECTORYW_OPENED_NAMESPACE_V1'
        api_path = $windowsRoot
        environment_system_root = $systemRoot
        os_version = $ExpectedOsVersion
    }
    Assert-D32PowerShellAuthorityExactJsonRecord -Element $proofElement -Fields @('proof_type','api_path','environment_system_root','os_version') -Name 'pinned Windows OS source proof'
    if (-not (Test-D32PowerShellAuthorityJsonMatchesObject -Element $proofElement -Value $expectedProof)) {
        throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: pinned Windows OS source proof differs from the opened live root/version'
    }

    $distributionElement = $Element.GetProperty('distribution')
    Assert-D32PowerShellAuthorityExactJsonRecord -Element $distributionElement -Fields @('root_path','inventory_sha256','directories','files','protected_ancestors','trusted_writer_sids') -Name 'pinned Windows OS finite distribution'
    if ((Get-D32PowerShellAuthorityJsonString $distributionElement 'root_path') -cne $windowsRoot -or
        (Get-D32PowerShellAuthorityJsonString $distributionElement 'inventory_sha256') -cnotmatch '^[0-9a-f]{64}$') {
        throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: pinned Windows OS finite distribution root or digest is invalid'
    }
    $trustedWriters = @('S-1-5-18','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464','S-1-5-32-544')
    $trustedElement = $distributionElement.GetProperty('trusted_writer_sids')
    if ($trustedElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Array -or $trustedElement.GetArrayLength() -ne $trustedWriters.Count) {
        throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: pinned Windows OS trusted-writer list is missing or expanded'
    }
    for ($index = 0; $index -lt $trustedWriters.Count; $index++) {
        if ($trustedElement[$index].ValueKind -ne [System.Text.Json.JsonValueKind]::String -or $trustedElement[$index].GetString() -cne $trustedWriters[$index]) {
            throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: pinned Windows OS trusted-writer list changed or reordered'
        }
    }

    $directoryElement = $distributionElement.GetProperty('directories')
    $fileElement = $distributionElement.GetProperty('files')
    $ancestorElement = $distributionElement.GetProperty('protected_ancestors')
    $nativeElement = $Element.GetProperty('native_files')
    if ($directoryElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Array -or $directoryElement.GetArrayLength() -eq 0 -or
        $fileElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Array -or $fileElement.GetArrayLength() -eq 0 -or
        $ancestorElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Array -or
        $nativeElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Array -or $nativeElement.GetArrayLength() -ne $fileElement.GetArrayLength()) {
        throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: pinned Windows OS finite file/directory/ancestor arrays are missing or inconsistent'
    }
    $component = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $Element
    $directoryPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $directoryIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $previousPath = ''
    $rootDirectorySeen = $false
    foreach ($recordElement in $directoryElement.EnumerateArray()) {
        Assert-D32PowerShellAuthorityExactJsonRecord -Element $recordElement -Fields @('kind','path','volume_serial_hex','file_id_hex','owner_sid','security_descriptor_sddl','security_descriptor_sha256') -Name 'pinned Windows OS directory'
        $record = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $recordElement
        $path = [string]$record.path
        if ($record.kind -cne 'directory' -or -not [IO.Path]::IsPathRooted($path) -or [IO.Path]::GetFullPath($path) -cne $path -or
            -not (Test-D32PowerShellAuthorityPathWithin -Child $path -Parent $windowsRoot) -or
            [StringComparer]::OrdinalIgnoreCase.Compare($previousPath, $path) -ge 0 -or -not $directoryPaths.Add($path) -or
            [string]$record.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or [string]$record.file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
            [string]$record.owner_sid -cnotin $trustedWriters -or [string]::IsNullOrWhiteSpace([string]$record.security_descriptor_sddl) -or
            [string]$record.security_descriptor_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $record.security_descriptor_sha256 -cne [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes([string]$record.security_descriptor_sddl))).ToLowerInvariant() -or
            -not $directoryIds.Add(([string]$record.volume_serial_hex + ':' + [string]$record.file_id_hex))) {
            throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: pinned Windows OS directory path, order, alias, or security descriptor is invalid: $path"
        }
        if ([StringComparer]::OrdinalIgnoreCase.Equals($path, $windowsRoot)) { $rootDirectorySeen = $true }
        $previousPath = $path
    }
    if (-not $rootDirectorySeen) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: pinned Windows OS namespace does not include its opened root directory' }
    foreach ($path in $directoryPaths) {
        if ([StringComparer]::OrdinalIgnoreCase.Equals($path, $windowsRoot)) { continue }
        if (-not $directoryPaths.Contains([IO.Path]::GetDirectoryName($path))) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: pinned Windows OS directory parent is absent: $path" }
    }

    $expectedAncestors = [System.Collections.Generic.List[string]]::new()
    $ancestorPath = [IO.Path]::GetDirectoryName($windowsRoot)
    while (-not [String]::IsNullOrWhiteSpace($ancestorPath)) {
        $ancestorPath = [IO.Path]::GetFullPath($ancestorPath)
        $expectedAncestors.Add($ancestorPath)
        if ([StringComparer]::OrdinalIgnoreCase.Equals($ancestorPath, [IO.Path]::GetPathRoot($ancestorPath))) { break }
        $ancestorPath = [IO.Path]::GetDirectoryName($ancestorPath)
    }
    $expectedAncestorArray = $expectedAncestors.ToArray()
    [Array]::Sort($expectedAncestorArray, [StringComparer]::OrdinalIgnoreCase)
    if ($ancestorElement.GetArrayLength() -ne $expectedAncestorArray.Count) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: pinned Windows OS ancestor chain is incomplete or expanded' }
    $ancestorIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    for ($index = 0; $index -lt $expectedAncestorArray.Count; $index++) {
        $recordElement = $ancestorElement[$index]
        Assert-D32PowerShellAuthorityExactJsonRecord -Element $recordElement -Fields @('kind','path','volume_serial_hex','file_id_hex','owner_sid','security_descriptor_sddl','security_descriptor_sha256') -Name 'pinned Windows OS protected ancestor'
        $record = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $recordElement
        if ($record.kind -cne 'ancestor' -or [string]$record.path -cne $expectedAncestorArray[$index] -or
            [string]$record.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or [string]$record.file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
            [string]$record.owner_sid -cnotin $trustedWriters -or [string]::IsNullOrWhiteSpace([string]$record.security_descriptor_sddl) -or
            [string]$record.security_descriptor_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $record.security_descriptor_sha256 -cne [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes([string]$record.security_descriptor_sddl))).ToLowerInvariant() -or
            -not $ancestorIds.Add(([string]$record.volume_serial_hex + ':' + [string]$record.file_id_hex)) -or
            $directoryIds.Contains(([string]$record.volume_serial_hex + ':' + [string]$record.file_id_hex))) {
            throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: pinned Windows OS protected ancestor path, order, alias, or security descriptor is invalid: $($record.path)"
        }
    }

    $filePaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $fileIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $previousPath = ''
    for ($index = 0; $index -lt $fileElement.GetArrayLength(); $index++) {
        $recordElement = $fileElement[$index]
        Assert-D32PowerShellAuthorityExactJsonRecord -Element $recordElement -Fields @('kind','path','bytes','sha256','volume_serial_hex','file_id_hex','owner_sid','security_descriptor_sddl','security_descriptor_sha256') -Name 'pinned Windows OS resolver file'
        $record = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $recordElement
        $path = [string]$record.path
        if ($record.kind -cne 'file' -or -not [IO.Path]::IsPathRooted($path) -or [IO.Path]::GetFullPath($path) -cne $path -or
            -not (Test-D32PowerShellAuthorityPathWithin -Child $path -Parent $windowsRoot) -or
            -not $directoryPaths.Contains([IO.Path]::GetDirectoryName($path)) -or
            [StringComparer]::OrdinalIgnoreCase.Compare($previousPath, $path) -ge 0 -or -not $filePaths.Add($path) -or
            [Int64]$record.bytes -le 0 -or [string]$record.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$record.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or [string]$record.file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
            [string]$record.owner_sid -cnotin $trustedWriters -or [string]::IsNullOrWhiteSpace([string]$record.security_descriptor_sddl) -or
            [string]$record.security_descriptor_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $record.security_descriptor_sha256 -cne [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes([string]$record.security_descriptor_sddl))).ToLowerInvariant() -or
            -not $fileIds.Add(([string]$record.volume_serial_hex + ':' + [string]$record.file_id_hex)) -or
            $directoryIds.Contains(([string]$record.volume_serial_hex + ':' + [string]$record.file_id_hex)) -or
            $ancestorIds.Contains(([string]$record.volume_serial_hex + ':' + [string]$record.file_id_hex))) {
            throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: pinned Windows OS resolver file path, order, alias, content, or security descriptor is invalid: $path"
        }
        if (-not (Test-D32PowerShellAuthorityJsonMatchesObject -Element $nativeElement[$index] -Value $record)) {
            throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: pinned Windows OS native source list differs from its static file inventory: $path"
        }
        $previousPath = $path
    }

    $distributionDigest = Get-D32PowerShellAuthorityRuntimeInventoryDigest -Directories ([object[]]$component.distribution.directories) `
        -Files ([object[]]$component.distribution.files) -Ancestors ([object[]]$component.distribution.protected_ancestors)
    if ($distributionDigest -cne [string]$component.distribution.inventory_sha256) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: pinned Windows OS finite distribution digest is invalid' }
    $componentDigestMaterial = [string]$distributionDigest + "`n" + (ConvertTo-D32PowerShellAuthorityJsonText -Value $expectedProof) + "`n"
    $componentDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes($componentDigestMaterial))).ToLowerInvariant()
    if ($componentDigest -cne [string]$component.inventory_sha256) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: pinned Windows OS component digest is invalid' }
    return ,$component
}

function Get-D32PowerShellAuthorityPinnedWindowsComponentSnapshot {
    param(
        [Parameter(Mandatory = $true)][System.Text.Json.JsonElement]$Element,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$DirectoryFences,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$OpenFiles
    )
    $windowsRoot = Get-D32PowerShellAuthorityWindowsRootPath
    $systemRoot = [IO.Path]::GetFullPath([string]$env:SystemRoot)
    $osVersion = [Environment]::OSVersion.VersionString
    $pinned = Assert-D32PowerShellAuthorityPinnedWindowsComponentShape -Element $Element -ExpectedWindowsRoot $windowsRoot -ExpectedSystemRoot $systemRoot -ExpectedOsVersion $osVersion
    Add-D32PowerShellAuthorityDirectoryChain -Directory $windowsRoot -Fences $DirectoryFences
    foreach ($directory in @($pinned.distribution.directories)) { Add-D32PowerShellAuthorityDirectoryChain -Directory ([string]$directory.path) -Fences $DirectoryFences }
    foreach ($ancestor in @($pinned.distribution.protected_ancestors)) { Add-D32PowerShellAuthorityDirectoryChain -Directory ([string]$ancestor.path) -Fences $DirectoryFences }

    $liveDirectories = [System.Collections.Generic.List[object]]::new()
    $directoryArray = $Element.GetProperty('distribution').GetProperty('directories')
    for ($index = 0; $index -lt $directoryArray.GetArrayLength(); $index++) {
        $expected = $pinned.distribution.directories[$index]
        $path = [string]$expected.path
        $key = $path.TrimEnd([char[]]@('\','/'))
        if ($key.Length -eq 2 -and $key[1] -eq ':') { $key += [IO.Path]::DirectorySeparatorChar }
        $fence = $DirectoryFences[$key]
        if ($null -eq $fence -or $fence.Handle.IsClosed -or $fence.Handle.IsInvalid -or [string]$fence.Path -cne $path) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: pinned Windows OS directory fence is missing or aliased: $path" }
        $identity = Get-D32PowerShellAuthorityHandleIdentity -Handle $fence.Handle
        $security = Get-D32PowerShellAuthorityObjectSecurity -Path $path -IsDirectory:$true -Handle $fence.Handle
        if (($identity.Attributes -band [int][IO.FileAttributes]::Directory) -eq 0 -or ($identity.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals((Get-D32PowerShellAuthorityFinalHandlePath -Handle $fence.Handle), $path) -or
            $identity.VolumeSerialHex -cne [string]$expected.volume_serial_hex -or $identity.FileIdHex -cne [string]$expected.file_id_hex -or
            -not (Test-D32PowerShellAuthorityProtectedSecurity -Security $security -IsDirectory:$true) -or
            $security.OwnerSid -cne [string]$expected.owner_sid -or $security.Sddl -cne [string]$expected.security_descriptor_sddl -or
            $security.AclSha256 -cne [string]$expected.security_descriptor_sha256) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: pinned Windows OS directory identity/security changed: $path" }
        $actual = [ordered]@{ kind = 'directory'; path = [string]$fence.Path; volume_serial_hex = [string]$identity.VolumeSerialHex; file_id_hex = [string]$identity.FileIdHex; owner_sid = [string]$security.OwnerSid; security_descriptor_sddl = [string]$security.Sddl; security_descriptor_sha256 = [string]$security.AclSha256 }
        if (-not (Test-D32PowerShellAuthorityJsonMatchesObject -Element $directoryArray[$index] -Value $actual)) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: reopened Windows OS directory differs from its exact caller pin: $path" }
        $liveDirectories.Add($actual)
    }

    $liveAncestors = [System.Collections.Generic.List[object]]::new()
    $ancestorArray = $Element.GetProperty('distribution').GetProperty('protected_ancestors')
    for ($index = 0; $index -lt $ancestorArray.GetArrayLength(); $index++) {
        $expected = $pinned.distribution.protected_ancestors[$index]
        $path = [string]$expected.path
        $key = $path.TrimEnd([char[]]@('\','/'))
        if ($key.Length -eq 2 -and $key[1] -eq ':') { $key += [IO.Path]::DirectorySeparatorChar }
        $fence = $DirectoryFences[$key]
        if ($null -eq $fence -or $fence.Handle.IsClosed -or $fence.Handle.IsInvalid -or [string]$fence.Path -cne $path) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: pinned Windows OS ancestor fence is missing or aliased: $path" }
        $identity = Get-D32PowerShellAuthorityHandleIdentity -Handle $fence.Handle
        $security = Get-D32PowerShellAuthorityObjectSecurity -Path $path -IsDirectory:$true -Handle $fence.Handle
        if (($identity.Attributes -band [int][IO.FileAttributes]::Directory) -eq 0 -or ($identity.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals((Get-D32PowerShellAuthorityFinalHandlePath -Handle $fence.Handle), $path) -or
            $identity.VolumeSerialHex -cne [string]$expected.volume_serial_hex -or $identity.FileIdHex -cne [string]$expected.file_id_hex -or
            -not (Test-D32PowerShellAuthorityProtectedSecurity -Security $security -IsDirectory:$true -IsProtectedAncestor) -or
            $security.OwnerSid -cne [string]$expected.owner_sid -or $security.Sddl -cne [string]$expected.security_descriptor_sddl -or
            $security.AclSha256 -cne [string]$expected.security_descriptor_sha256) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: pinned Windows OS ancestor identity/security changed: $path" }
        $actual = [ordered]@{ kind = 'ancestor'; path = [string]$fence.Path; volume_serial_hex = [string]$identity.VolumeSerialHex; file_id_hex = [string]$identity.FileIdHex; owner_sid = [string]$security.OwnerSid; security_descriptor_sddl = [string]$security.Sddl; security_descriptor_sha256 = [string]$security.AclSha256 }
        if (-not (Test-D32PowerShellAuthorityJsonMatchesObject -Element $ancestorArray[$index] -Value $actual)) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: reopened Windows OS ancestor differs from its exact caller pin: $path" }
        $liveAncestors.Add($actual)
    }

    $liveFiles = [System.Collections.Generic.List[object]]::new()
    $fileArray = $Element.GetProperty('distribution').GetProperty('files')
    for ($index = 0; $index -lt $fileArray.GetArrayLength(); $index++) {
        $expected = $pinned.distribution.files[$index]
        $snapshot = Open-D32PowerShellAuthorityFile -Path ([string]$expected.path) -DirectoryFences $DirectoryFences
        $OpenFiles.Add($snapshot)
        if (-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $snapshot.Security -IsDirectory:$false)) {
            throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: pinned Windows OS file namespace is not protected: $($expected.path)"
        }
        $actual = [ordered]@{ kind = 'file'; path = [string]$snapshot.Record.path; bytes = [Int64]$snapshot.Record.bytes; sha256 = [string]$snapshot.Record.sha256; volume_serial_hex = [string]$snapshot.Record.volume_serial_hex; file_id_hex = [string]$snapshot.Record.file_id_hex; owner_sid = [string]$snapshot.Security.OwnerSid; security_descriptor_sddl = [string]$snapshot.Security.Sddl; security_descriptor_sha256 = [string]$snapshot.Security.AclSha256 }
        if (-not (Test-D32PowerShellAuthorityJsonMatchesObject -Element $fileArray[$index] -Value $actual)) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: reopened Windows OS resolver file differs from its exact caller pin: $($expected.path)" }
        $liveFiles.Add($actual)
    }

    $distribution = [ordered]@{
        root_path = [string]$pinned.distribution.root_path
        inventory_sha256 = ''
        directories = $liveDirectories.ToArray()
        files = $liveFiles.ToArray()
        protected_ancestors = $liveAncestors.ToArray()
        trusted_writer_sids = @('S-1-5-18','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464','S-1-5-32-544')
    }
    $distribution.inventory_sha256 = Get-D32PowerShellAuthorityRuntimeInventoryDigest -Directories $distribution.directories -Files $distribution.files -Ancestors $distribution.protected_ancestors
    $sourceProof = [ordered]@{ proof_type = 'GET_WINDOWSDIRECTORYW_OPENED_NAMESPACE_V1'; api_path = $windowsRoot; environment_system_root = $systemRoot; os_version = $osVersion }
    $digestMaterial = [string]$distribution.inventory_sha256 + "`n" + (ConvertTo-D32PowerShellAuthorityJsonText -Value $sourceProof) + "`n"
    $componentDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes($digestMaterial))).ToLowerInvariant()
    $rootKey = $windowsRoot.TrimEnd([char[]]@('\','/'))
    if ($rootKey.Length -eq 2 -and $rootKey[1] -eq ':') { $rootKey += [IO.Path]::DirectorySeparatorChar }
    $rootFence = $DirectoryFences[$rootKey]
    if ($null -eq $rootFence) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: Windows OS root identity is absent from opened directory fences' }
    $actualComponent = [ordered]@{
        component_type = 'MICROSOFT_WINDOWS_OS_INSTALLATION'
        version = $osVersion
        root_path = $windowsRoot
        root_volume_serial_hex = [string]$rootFence.VolumeSerialHex
        root_file_id_hex = [string]$rootFence.FileIdHex
        inventory_sha256 = $componentDigest
        source_proof = $sourceProof
        distribution = $distribution
        native_files = $liveFiles.ToArray()
    }
    if (-not (Test-D32PowerShellAuthorityJsonMatchesObject -Element $Element -Value $actualComponent)) {
        throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: independently pinned Windows OS static authority changed during exact live re-open'
    }
    return [PSCustomObject]@{ Component = $actualComponent; OpenFiles = $OpenFiles; DirectoryFences = $DirectoryFences }
}

function Get-D32PowerShellAuthorityRuntimeDistributionSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$PowerShellRoot,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$DirectoryFences,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$OpenFiles,
        [ValidateRange(0, 4096)][int]$MaximumFiles = 0,
        [ValidateRange(0, 1024)][int]$MaximumDirectories = 0,
        [ValidateRange(0, 2147483648)][long]$MaximumAggregateBytes = 0,
        [ValidateRange(0, 268435456)][long]$MaximumSingleFileBytes = 0
    )
    $root = [IO.Path]::GetFullPath($PowerShellRoot)
    Add-D32PowerShellAuthorityDirectoryChain -Directory $root -Fences $DirectoryFences
    $directories = [System.Collections.Generic.List[object]]::new()
    $files = [System.Collections.Generic.List[object]]::new()
    [decimal]$aggregateBytes = 0
    $identitySet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $pending = [System.Collections.Generic.Stack[string]]::new()
    $pending.Push($root)
    while ($pending.Count -gt 0) {
        Assert-D32PowerShellAuthorityPreparationDeadline
        $directory = [IO.Path]::GetFullPath($pending.Pop())
        $directoryKey = $directory.TrimEnd([char[]]@('\','/'))
        if ($directoryKey.Length -eq 2 -and $directoryKey[1] -eq ':') { $directoryKey += [IO.Path]::DirectorySeparatorChar }
        $fence = $DirectoryFences[$directoryKey]
        if ($null -eq $fence -or -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$fence.Path, $directory)) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: full distribution directory handle is missing: $directory" }
        $dirIdentity = Get-D32PowerShellAuthorityHandleIdentity -Handle $fence.Handle
        if (($dirIdentity.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not $identitySet.Add(([string]$dirIdentity.VolumeSerialHex + ':' + [string]$dirIdentity.FileIdHex))) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: runtime distribution directory is reparsed or aliased: $directory" }
        if ($MaximumDirectories -gt 0 -and $directories.Count -ge $MaximumDirectories) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: bounded runtime directory count exceeded before opening another entry' }
        $directories.Add([ordered]@{ kind = 'directory'; path = $directory; volume_serial_hex = [string]$fence.VolumeSerialHex; file_id_hex = [string]$fence.FileIdHex; owner_sid = [string]$fence.OwnerSid; security_descriptor_sddl = [string]$fence.Sddl; security_descriptor_sha256 = [string]$fence.AclSha256 })
        $entries = [System.Collections.Generic.List[string]]::new()
        foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($directory)) {
            Assert-D32PowerShellAuthorityPreparationDeadline
            if ($MaximumFiles -gt 0 -and ($files.Count + $entries.Count) -ge ($MaximumFiles + $MaximumDirectories)) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: bounded runtime directory-entry enumeration exceeded its fixed ceiling' }
            $entries.Add([IO.Path]::GetFullPath([string]$entry))
        }
        $entryArray = $entries.ToArray()
        [Array]::Sort($entryArray, [StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $entryArray) {
            Assert-D32PowerShellAuthorityPreparationDeadline
            $attributes = [IO.File]::GetAttributes($entry)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: runtime distribution contains a reparse point: $entry" }
            if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) {
                Add-D32PowerShellAuthorityDirectoryChain -Directory $entry -Fences $DirectoryFences
                $pending.Push($entry)
                continue
            }
            if ($MaximumFiles -gt 0 -and $files.Count -ge $MaximumFiles) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: bounded runtime file count exceeded before opening another file' }
            if ($MaximumSingleFileBytes -gt 0 -or $MaximumAggregateBytes -gt 0) {
                $length = [Int64]([IO.FileInfo]::new($entry)).Length
                if ($MaximumSingleFileBytes -gt 0 -and $length -gt $MaximumSingleFileBytes) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: bounded runtime single-file content limit exceeded before open' }
                if ($MaximumAggregateBytes -gt 0 -and $aggregateBytes + [decimal]$length -gt [decimal]$MaximumAggregateBytes) {
                    throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: bounded runtime aggregate content limit exceeded before open'
                }
            }
            $snapshotMaximum = if ($MaximumSingleFileBytes -gt 0) { $MaximumSingleFileBytes } else { [Int32]::MaxValue }
            $snapshot = Open-D32PowerShellAuthorityFile -Path $entry -DirectoryFences $DirectoryFences -MaximumBytes $snapshotMaximum
            $OpenFiles.Add($snapshot)
            $aggregateBytes += [decimal]$snapshot.Record.bytes
            if ($MaximumAggregateBytes -gt 0 -and $aggregateBytes -gt [decimal]$MaximumAggregateBytes) { $snapshot.Stream.Dispose(); throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: bounded runtime aggregate content limit exceeded' }
            $id = [string]$snapshot.Record.volume_serial_hex + ':' + [string]$snapshot.Record.file_id_hex
            if (-not $identitySet.Add($id)) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: runtime distribution has duplicate object identities: $entry" }
            $files.Add([ordered]@{ kind = 'file'; path = [string]$snapshot.Record.path; bytes = [Int64]$snapshot.Record.bytes; sha256 = [string]$snapshot.Record.sha256; volume_serial_hex = [string]$snapshot.Record.volume_serial_hex; file_id_hex = [string]$snapshot.Record.file_id_hex; owner_sid = [string]$snapshot.Security.OwnerSid; security_descriptor_sddl = [string]$snapshot.Security.Sddl; security_descriptor_sha256 = [string]$snapshot.Security.AclSha256 })
        }
    }
    $ancestorRecords = [System.Collections.Generic.List[object]]::new()
    $ancestor = [IO.Path]::GetDirectoryName($root)
    while (-not [String]::IsNullOrWhiteSpace($ancestor)) {
        $ancestorFull = [IO.Path]::GetFullPath($ancestor)
        $ancestorKey = $ancestorFull.TrimEnd([char[]]@('\','/'))
        if ($ancestorKey.Length -eq 2 -and $ancestorKey[1] -eq ':') { $ancestorKey += [IO.Path]::DirectorySeparatorChar }
        $fence = $DirectoryFences[$ancestorKey]
        if ($null -eq $fence) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: protected runtime ancestor handle is missing: $ancestorFull" }
        $ancestorRecords.Add([ordered]@{ kind = 'ancestor'; path = [string]$fence.Path; volume_serial_hex = [string]$fence.VolumeSerialHex; file_id_hex = [string]$fence.FileIdHex; owner_sid = [string]$fence.OwnerSid; security_descriptor_sddl = [string]$fence.Sddl; security_descriptor_sha256 = [string]$fence.AclSha256 })
        if ([StringComparer]::OrdinalIgnoreCase.Equals($ancestorFull, [IO.Path]::GetPathRoot($ancestorFull).TrimEnd([char[]]@('\','/')))) { break }
        $ancestor = [IO.Path]::GetDirectoryName($ancestorFull)
    }
    $sortedDirectories = [System.Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($record in $directories) { $sortedDirectories.Add([string]$record.path,$record) }
    $sortedFiles = [System.Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($record in $files) { $sortedFiles.Add([string]$record.path,$record) }
    $sortedAncestors = [System.Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($record in $ancestorRecords) { $sortedAncestors.Add([string]$record.path,$record) }
    $directoryArray = @($sortedDirectories.Values); $fileArray = @($sortedFiles.Values); $ancestorArray = @($sortedAncestors.Values)
    $digest = Get-D32PowerShellAuthorityRuntimeInventoryDigest -Directories $directoryArray -Files $fileArray -Ancestors $ancestorArray
    return [ordered]@{ root_path = $root; inventory_sha256 = $digest; directories = $directoryArray; files = $fileArray; protected_ancestors = $ancestorArray; trusted_writer_sids = @('S-1-5-18','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464','S-1-5-32-544') }
}

function Get-D32PowerShellAuthorityProtectedAbsenceWitnessSha256 {
    param([Parameter(Mandatory = $true)][string]$RolePath, [Parameter(Mandatory = $true)][object]$ParentDirectoryRecord)
    $fullPath = [IO.Path]::GetFullPath($RolePath)
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName($fullPath),[string]$ParentDirectoryRecord.path) -or
        [string]$ParentDirectoryRecord.kind -cne 'directory' -or
        [string]$ParentDirectoryRecord.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or
        [string]$ParentDirectoryRecord.file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$ParentDirectoryRecord.security_descriptor_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]::IsNullOrWhiteSpace([string]$ParentDirectoryRecord.owner_sid) -or
        [string]::IsNullOrWhiteSpace([string]$ParentDirectoryRecord.security_descriptor_sddl)) {
        throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: protected absence witness parent is not a complete V2 directory identity/ACL record'
    }
    $parent = [ordered]@{
        kind=[string]$ParentDirectoryRecord.kind;path=[string]$ParentDirectoryRecord.path
        volume_serial_hex=[string]$ParentDirectoryRecord.volume_serial_hex;file_id_hex=[string]$ParentDirectoryRecord.file_id_hex
        owner_sid=[string]$ParentDirectoryRecord.owner_sid;security_descriptor_sddl=[string]$ParentDirectoryRecord.security_descriptor_sddl
        security_descriptor_sha256=[string]$ParentDirectoryRecord.security_descriptor_sha256
    }
    $projection = [ordered]@{policy_id='D32_NON_SOURCE_L1_PROTECTED_ABSENCE_V1';role_path=$fullPath;parent_directory=$parent}
    $text = ConvertTo-D32PowerShellAuthorityJsonText -Value $projection
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($text)
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

function New-D32PowerShellAuthorityNonSourceL1RuntimeContentCandidateFromV2Inputs {
    param([Parameter(Mandatory = $true)][string]$CandidateSha, [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][object]$RepositoryIdentity, [Parameter(Mandatory = $true)][object]$RuntimeFileReference,
        [Parameter(Mandatory = $true)][string]$PowerShellHome, [Parameter(Mandatory = $true)][string]$SystemRoot,
        [Parameter(Mandatory = $true)][object]$Distribution, [Parameter(Mandatory = $true)][object[]]$OsSecurityComponents,
        [Parameter(Mandatory = $true)][object]$UtilityManifestReference, [Parameter(Mandatory = $true)][object[]]$UtilityFiles,
        [Parameter(Mandatory = $true)][object]$StartupFileStates,
        [AllowEmptyCollection()][object[]]$TrustedPlatformAssemblyReferences = @(),
        [AllowEmptyCollection()][object[]]$NativeSearchDirectoryRecords = @(),
        [string[]]$InputGaps = @())
    $gaps = [System.Collections.Generic.List[string]]::new()
    foreach ($gap in $InputGaps) { if (-not [string]::IsNullOrWhiteSpace([string]$gap) -and -not $gaps.Contains([string]$gap)) { $gaps.Add([string]$gap) } }
    if ($CandidateSha -cnotmatch '^[0-9a-f]{40}$') { $gaps.Add('candidate_sha is not an exact lowercase 40-hex source-candidate pin') }
    if ($TrustedPlatformAssemblyReferences.Count -lt 1) { $gaps.Add('fixed target-runtime trusted-platform-assembly list is unavailable from non-observer static inputs') }
    if ($NativeSearchDirectoryRecords.Count -lt 1) { $gaps.Add('fixed target-runtime native-search directory list is unavailable from non-observer static inputs') }
    if ($null -eq $Distribution -or $null -eq $RuntimeFileReference -or $null -eq $RepositoryIdentity -or
        $null -eq $StartupFileStates -or $null -eq $UtilityManifestReference -or $OsSecurityComponents.Count -ne 2) {
        $gaps.Add('one or more required V2 runtime, OS/Defender, Utility, repository, or startup-input witnesses are missing')
    }
    if ($gaps.Count -gt 0) {
        return [PSCustomObject][ordered]@{gate_authority='NONE';status='BLOCKED_INPUT_GAPS';candidate=$null;candidate_json=$null;candidate_sha256=$null;gaps=@($gaps.ToArray())}
    }
    try {
        $tpaByPath = [System.Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($reference in $TrustedPlatformAssemblyReferences) {
            Assert-D32PowerShellAuthorityPreparationDeadline
            if (-not (Test-D32BoundedCompilerDiagnosticFileReferenceShape $reference)) { throw 'target-runtime TPA input is not a complete V2 file reference' }
            $path = [string]$reference.path
            if ([string]::IsNullOrWhiteSpace($path) -or $tpaByPath.ContainsKey($path)) { throw 'duplicate or empty target-runtime TPA reference' }
            $tpaByPath.Add($path,[ordered]@{path=$path;bytes=[Int64]$reference.bytes;sha256=[string]$reference.sha256
                volume_serial_hex=[string]$reference.volume_serial_hex;file_id_hex=[string]$reference.file_id_hex})
        }
        $tpaArray = @($tpaByPath.Values)
        $nativeByPath = [System.Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($record in $NativeSearchDirectoryRecords) {
            Assert-D32PowerShellAuthorityPreparationDeadline
            if ([string]$record.kind -cne 'directory' -or
                -not (Test-D32BoundedDiagnosticSourceProofNonSourceL1RuntimeDirectoryRecord $record)) {
                throw 'target-runtime native-search input is not a complete V2 directory record'
            }
            $path = [string]$record.path
            if ([string]::IsNullOrWhiteSpace($path) -or $nativeByPath.ContainsKey($path)) { throw 'duplicate or empty target-runtime native directory reference' }
            $nativeByPath.Add($path,[ordered]@{kind='directory';path=$path;volume_serial_hex=[string]$record.volume_serial_hex
                file_id_hex=[string]$record.file_id_hex;owner_sid=[string]$record.owner_sid;security_descriptor_sddl=[string]$record.security_descriptor_sddl
                security_descriptor_sha256=[string]$record.security_descriptor_sha256})
        }
        $nativeArray = @($nativeByPath.Values)
        $utilityDigest = Get-D32PowerShellAuthorityInventoryDigest -Role 'Utility' -Files $UtilityFiles
        $runtimeHome = [IO.Path]::GetFullPath($PowerShellHome)
        $systemRootFull = [IO.Path]::GetFullPath($SystemRoot)
        $manifestPath = [IO.Path]::GetFullPath([IO.Path]::Combine($runtimeHome,'Modules','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Utility.psd1'))
        if ([string]$UtilityManifestReference.path -cne $manifestPath) { throw 'fixed Utility manifest is not the existing V2 Utility role' }
        $candidate = [PSCustomObject][ordered]@{
            schema_version=1;record_type='D32_NON_SOURCE_L1_RUNTIME_CONTENT_AUTHORITY_V1';purpose='NON_SOURCE_L1_RUNTIME_ONLY';gate_authority='NONE'
            status='CANDIDATE_FOR_COORDINATOR_PIN';candidate_sha=$CandidateSha;source_repo=[IO.Path]::GetFullPath($Repository)
            repository_identity=[PSCustomObject][ordered]@{volume_serial_hex=[string]$RepositoryIdentity.VolumeSerialHex;file_id_hex=[string]$RepositoryIdentity.FileIdHex}
            powershell_runtime=[PSCustomObject][ordered]@{path=[string]$RuntimeFileReference.path;bytes=[Int64]$RuntimeFileReference.bytes
                sha256=[string]$RuntimeFileReference.sha256;volume_serial_hex=[string]$RuntimeFileReference.volume_serial_hex
                file_id_hex=[string]$RuntimeFileReference.file_id_hex;powershell_home=$runtimeHome;system_root=$systemRootFull}
            distribution=$Distribution
            resolver_policy=[PSCustomObject][ordered]@{policy_id='D32_POWERSHELL_RESOLVER_DOMAIN_V2';managed_distribution_root=$runtimeHome
                managed_os_root=$systemRootFull;native_application_root=$runtimeHome;native_system_root=$systemRootFull
                native_search_flags=@('LOAD_LIBRARY_SEARCH_APPLICATION_DIR','LOAD_LIBRARY_SEARCH_SYSTEM32')
                forbidden_sources=@('CWD','PATH','USER_PSMODULEPATH','STARTUP_HOOKS','EXTERNAL_ASSEMBLIES','UNPINNED_DLL_DIRECTORIES')
                os_security_components=@($OsSecurityComponents)}
            module_policy=[PSCustomObject][ordered]@{policy_id='NON_SOURCE_L1_UTILITY_ONLY_V1'
                controller_utility_manifest=[PSCustomObject][ordered]@{path=[string]$UtilityManifestReference.path;bytes=[Int64]$UtilityManifestReference.bytes
                    sha256=[string]$UtilityManifestReference.sha256;volume_serial_hex=[string]$UtilityManifestReference.volume_serial_hex
                    file_id_hex=[string]$UtilityManifestReference.file_id_hex};controller_utility_inventory_sha256=$utilityDigest
                controller_import_count=1L;reader_import_count=0L;controller_allowed_commands=@('Add-Type','ConvertTo-Json');reader_wait_policy='MANAGED_FINITE_WAIT_V1'}
            startup_inputs=[PSCustomObject][ordered]@{policy_id='D32_NON_SOURCE_L1_STARTUP_INPUTS_V1'
                deps=$StartupFileStates.deps;runtime_config=$StartupFileStates.runtime_config;protected_startup_config=$StartupFileStates.protected_startup_config
                trusted_platform_assemblies=[PSCustomObject][ordered]@{count=[Int64]$tpaArray.Count
                    inventory_sha256=(Get-D32PowerShellAuthorityInventoryDigest -Role 'D32_NON_SOURCE_L1_TRUSTED_PLATFORM_ASSEMBLIES_V1' -Files $tpaArray);paths=$tpaArray}
                native_search=[PSCustomObject][ordered]@{inventory_sha256=(Get-D32PowerShellAuthorityRuntimeInventoryDigest -Directories $nativeArray -Files @() -Ancestors @());paths=$nativeArray}
                startup_hooks=[PSCustomObject][ordered]@{state='ABSENT';paths=@()};profiling=[PSCustomObject][ordered]@{enabled=$false;variables=@()}}
            limits=[PSCustomObject][ordered]@{runtime_bytes=4194304L;file_count=4096L;directory_count=1024L;aggregate_bytes=2147483648L
                single_file_bytes=268435456L;resolver_list_entries=1024L}
        }
        $json = ConvertTo-D32PowerShellAuthorityJsonText -Value $candidate
        $jsonBytes = [Text.UTF8Encoding]::new($false,$true).GetBytes($json)
        if ($jsonBytes.Length -le 0 -or $jsonBytes.Length -gt 4194304) { throw 'fixed runtime-content candidate JSON is empty or exceeds the 4 MiB authority limit' }
        $document = [System.Text.Json.JsonDocument]::Parse($json)
        try {
            if ($document.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
                (Test-D32PowerShellAuthorityJsonDuplicates -Element $document.RootElement)) {
                throw 'fixed runtime-content candidate JSON failed strict object/duplicate-key readback'
            }
            $readback = ConvertFrom-D32PowerShellAuthorityJsonElement -Element $document.RootElement
        } finally { $document.Dispose() }
        if (-not (Test-D32BoundedDiagnosticSourceProofNonSourceL1RuntimeContentAuthorityShape -Document $readback `
                -ExpectedCandidateSha $CandidateSha -Repository $Repository)) {
            throw 'fixed runtime-content candidate strict JSON readback did not pass the exact consumer'
        }
        return [PSCustomObject][ordered]@{gate_authority='NONE';status='CANDIDATE_FOR_COORDINATOR_PIN';candidate=$readback
            candidate_json=$json;candidate_sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($jsonBytes)).ToLowerInvariant();gaps=@()}
    } catch {
        $gaps.Add([string]$_.Exception.Message)
        return [PSCustomObject][ordered]@{gate_authority='NONE';status='BLOCKED_INPUT_GAPS';candidate=$null;candidate_json=$null;candidate_sha256=$null;gaps=@($gaps.ToArray())}
    }
}

function Get-D32PowerShellAuthorityNonSourceL1StaticRuntimeAssets {
    param(
        [Parameter(Mandatory = $true)][byte[]]$DepsBytes,
        [Parameter(Mandatory = $true)][string]$PowerShellRoot,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$DistributionFiles
    )
    if ($DepsBytes.Length -le 0 -or $DepsBytes.Length -gt 4194304) { throw 'fixed pwsh.deps.json content is empty or exceeds its 4 MiB limit' }
    $jsonText = [Text.UTF8Encoding]::new($false,$true).GetString($DepsBytes)
    $document = [System.Text.Json.JsonDocument]::Parse($jsonText)
    try {
        if ($document.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
            (Test-D32PowerShellAuthorityJsonDuplicates -Element $document.RootElement)) {
            throw 'fixed pwsh.deps.json is not a duplicate-free JSON object'
        }
        $root = $document.RootElement
        $fixedPowerShellRoot = [IO.Path]::GetFullPath($PowerShellRoot)
        $runtimeTarget = $root.GetProperty('runtimeTarget')
        $targets = $root.GetProperty('targets')
        $libraries = $root.GetProperty('libraries')
        if ($runtimeTarget.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
            $targets.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
            $libraries.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
            $runtimeTarget.GetProperty('name').ValueKind -ne [System.Text.Json.JsonValueKind]::String) {
            throw 'fixed pwsh.deps.json omits its exact runtime target, target map, or library map'
        }
        $targetName = $runtimeTarget.GetProperty('name').GetString()
        if ([string]::IsNullOrWhiteSpace($targetName) -or $targetName.Length -gt 512 -or $targetName.IndexOfAny([char[]]@("`0",'\')) -ge 0) {
            throw 'fixed pwsh.deps.json runtime target name is not a bounded framework/RID label'
        }
        $target = $targets.GetProperty($targetName)
        if ($target.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { throw 'fixed pwsh.deps.json runtime target is not an object' }
        $packageFolders = [System.Text.Json.JsonElement]::new()
        if ($root.TryGetProperty('packageFolders',[ref]$packageFolders)) {
            if ($packageFolders.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { throw 'fixed pwsh.deps.json packageFolders is not a bounded object' }
            $packageFolderCount = 0
            foreach ($folder in $packageFolders.EnumerateObject()) {
                if (++$packageFolderCount -gt 64) { throw 'fixed pwsh.deps.json packageFolders exceeds its 64-entry bound' }
                if ($folder.Value.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
                    -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$folder.Name),$fixedPowerShellRoot)) {
                    throw 'fixed pwsh.deps.json contains a package folder outside the exact V2 PowerShell distribution root'
                }
            }
        }

        $fileByPath = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($file in $DistributionFiles) {
            Assert-D32PowerShellAuthorityPreparationDeadline
            $path = [string]$file.path
            if (-not $fileByPath.TryAdd($path,$file)) { throw "fixed PowerShell distribution repeats a file reference: $path" }
        }
        $tpaByPath = [System.Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
        $nativeByPath = [System.Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
        $libraryCount = 0
        $assetCount = 0
        foreach ($libraryProperty in $target.EnumerateObject()) {
            Assert-D32PowerShellAuthorityPreparationDeadline
            if (++$libraryCount -gt 4096) { throw 'fixed pwsh.deps.json target exceeds the 4096 library bound' }
            $libraryName = [string]$libraryProperty.Name
            $libraryMetadata = $libraries.GetProperty($libraryName)
            if ($libraryProperty.Value.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
                $libraryMetadata.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) {
                throw "fixed pwsh.deps.json library metadata is malformed: $libraryName"
            }
            $libraryPath = ''
            $pathElement = [System.Text.Json.JsonElement]::new()
            if ($libraryMetadata.TryGetProperty('path',[ref]$pathElement) -and $pathElement.ValueKind -eq [System.Text.Json.JsonValueKind]::String) { $libraryPath = [string]$pathElement.GetString() }
            foreach ($assetGroupName in @('runtime','native')) {
                    Assert-D32PowerShellAuthorityPreparationDeadline
                $assets = [System.Text.Json.JsonElement]::new()
                if (-not $libraryProperty.Value.TryGetProperty($assetGroupName,[ref]$assets)) { continue }
                if ($assets.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { throw "fixed pwsh.deps.json $assetGroupName assets are not an object: $libraryName" }
                foreach ($asset in $assets.EnumerateObject()) {
                    Assert-D32PowerShellAuthorityPreparationDeadline
                    if (++$assetCount -gt 4096) { throw 'fixed pwsh.deps.json asset count exceeds the 4096 bound' }
                    $assetPath = [string]$asset.Name
                    if ([string]::IsNullOrWhiteSpace($assetPath) -or $assetPath.IndexOfAny([char[]]@("`0",':')) -ge 0 -or
                        [IO.Path]::IsPathRooted($assetPath)) { throw "fixed pwsh.deps.json asset path is not relative: $assetPath" }
                    $extension = [IO.Path]::GetExtension($assetPath)
                    if ($extension -ine '.dll') { throw "fixed pwsh.deps.json $assetGroupName asset has an unsupported non-DLL target: $assetPath" }
                    $candidates = [System.Collections.Generic.List[string]]::new()
                    if (-not [string]::IsNullOrWhiteSpace($libraryPath)) { $candidates.Add([IO.Path]::GetFullPath([IO.Path]::Combine($fixedPowerShellRoot,$libraryPath,$assetPath))) }
                    $candidates.Add([IO.Path]::GetFullPath([IO.Path]::Combine($fixedPowerShellRoot,$assetPath)))
                    $selected = $null
                    foreach ($candidatePath in $candidates) {
                        Assert-D32PowerShellAuthorityPreparationDeadline
                        if (-not (Test-D32PowerShellAuthorityPathWithin -Child $candidatePath -Parent $fixedPowerShellRoot)) { throw "fixed pwsh.deps.json asset escapes PSHOME: $assetPath" }
                        if ($fileByPath.ContainsKey($candidatePath)) { $selected = $fileByPath[$candidatePath]; break }
                    }
                    if ($null -eq $selected) { throw "fixed pwsh.deps.json $assetGroupName asset has no exact V2 PowerShell file record: $assetPath" }
                    if ($assetGroupName -ceq 'runtime') {
                        $reference = [ordered]@{ path=[string]$selected.path; bytes=[Int64]$selected.bytes; sha256=[string]$selected.sha256
                            volume_serial_hex=[string]$selected.volume_serial_hex; file_id_hex=[string]$selected.file_id_hex }
                        if (-not $tpaByPath.ContainsKey([string]$reference.path)) { $tpaByPath.Add([string]$reference.path,$reference) }
                    }
                    else {
                        if (-not $nativeByPath.ContainsKey([string]$selected.path)) { $nativeByPath.Add([string]$selected.path,$selected) }
                    }
                }
            }
            $runtimeTargets = [System.Text.Json.JsonElement]::new()
            if ($libraryProperty.Value.TryGetProperty('runtimeTargets',[ref]$runtimeTargets)) {
                if ($runtimeTargets.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { throw "fixed pwsh.deps.json runtimeTargets are not an object: $libraryName" }
                foreach ($asset in $runtimeTargets.EnumerateObject()) {
                    Assert-D32PowerShellAuthorityPreparationDeadline
                    if (++$assetCount -gt 4096) { throw 'fixed pwsh.deps.json runtimeTarget count exceeds the 4096 bound' }
                    if ($asset.Value.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { throw "fixed pwsh.deps.json runtimeTarget metadata is malformed: $($asset.Name)" }
                    $assetTypeElement = [System.Text.Json.JsonElement]::new()
                    if (-not $asset.Value.TryGetProperty('assetType',[ref]$assetTypeElement) -or $assetTypeElement.ValueKind -ne [System.Text.Json.JsonValueKind]::String) {
                        throw "fixed pwsh.deps.json runtimeTarget lacks a fixed assetType: $($asset.Name)"
                    }
                    $assetType = [string]$assetTypeElement.GetString()
                    if ($assetType -cnotin @('runtime','native')) { throw "fixed pwsh.deps.json runtimeTarget type is not a fixed runtime/native asset: $assetType" }
                    $assetPath = [string]$asset.Name
                    if ([IO.Path]::GetExtension($assetPath) -ine '.dll') { throw "fixed pwsh.deps.json runtimeTarget has an unsupported non-DLL asset: $assetPath" }
                    if ([IO.Path]::IsPathRooted($assetPath) -or $assetPath.IndexOfAny([char[]]@("`0",':')) -ge 0) { throw "fixed pwsh.deps.json runtimeTarget path is not relative: $assetPath" }
                    $candidates = [System.Collections.Generic.List[string]]::new()
                    if (-not [string]::IsNullOrWhiteSpace($libraryPath)) { $candidates.Add([IO.Path]::GetFullPath([IO.Path]::Combine($fixedPowerShellRoot,$libraryPath,$assetPath))) }
                    $candidates.Add([IO.Path]::GetFullPath([IO.Path]::Combine($fixedPowerShellRoot,$assetPath)))
                    $selected = $null
                    foreach ($candidatePath in $candidates) {
                        Assert-D32PowerShellAuthorityPreparationDeadline
                        if (-not (Test-D32PowerShellAuthorityPathWithin -Child $candidatePath -Parent $fixedPowerShellRoot)) { throw "fixed pwsh.deps.json runtimeTarget escapes PSHOME: $assetPath" }
                        if ($fileByPath.ContainsKey($candidatePath)) { $selected = $fileByPath[$candidatePath]; break }
                    }
                    if ($null -eq $selected) { throw "fixed pwsh.deps.json runtimeTarget has no exact V2 PowerShell file record: $assetPath" }
                    if ($assetType -ceq 'runtime') {
                        $reference = [ordered]@{ path=[string]$selected.path; bytes=[Int64]$selected.bytes; sha256=[string]$selected.sha256
                            volume_serial_hex=[string]$selected.volume_serial_hex; file_id_hex=[string]$selected.file_id_hex }
                        if (-not $tpaByPath.ContainsKey([string]$reference.path)) { $tpaByPath.Add([string]$reference.path,$reference) }
                    }
                    else { if (-not $nativeByPath.ContainsKey([string]$selected.path)) { $nativeByPath.Add([string]$selected.path,$selected) } }
                }
            }
        }
        $entryAssemblyPath = [IO.Path]::GetFullPath([IO.Path]::Combine($fixedPowerShellRoot,'pwsh.dll'))
        if (-not $fileByPath.ContainsKey($entryAssemblyPath)) { throw 'fixed pwsh.dll entry assembly has no exact V2 PowerShell file record' }
        $entryFile = $fileByPath[$entryAssemblyPath]
        $entryReference = [ordered]@{ path=[string]$entryFile.path; bytes=[Int64]$entryFile.bytes; sha256=[string]$entryFile.sha256
            volume_serial_hex=[string]$entryFile.volume_serial_hex; file_id_hex=[string]$entryFile.file_id_hex }
        if (-not $tpaByPath.ContainsKey($entryAssemblyPath)) { $tpaByPath.Add($entryAssemblyPath,$entryReference) }
        $coreLibraryPath = [IO.Path]::GetFullPath([IO.Path]::Combine($fixedPowerShellRoot,'System.Private.CoreLib.dll'))
        if (-not $fileByPath.ContainsKey($coreLibraryPath)) { throw 'fixed System.Private.CoreLib.dll has no exact V2 PowerShell file record' }
        $coreLibraryFile = $fileByPath[$coreLibraryPath]
        $coreLibraryReference = [ordered]@{ path=[string]$coreLibraryFile.path; bytes=[Int64]$coreLibraryFile.bytes; sha256=[string]$coreLibraryFile.sha256
            volume_serial_hex=[string]$coreLibraryFile.volume_serial_hex; file_id_hex=[string]$coreLibraryFile.file_id_hex }
        if (-not $tpaByPath.ContainsKey($coreLibraryPath)) { $tpaByPath.Add($coreLibraryPath,$coreLibraryReference) }
        if ($tpaByPath.Count -lt 1 -or $tpaByPath.Count -gt 1024 -or $nativeByPath.Count -gt 1024) {
            throw 'fixed pwsh.deps.json resolver asset list is empty or exceeds its 1024-entry bound'
        }
        return [PSCustomObject]@{ TrustedPlatformAssemblyReferences=@($tpaByPath.Values); NativeAssetFiles=@($nativeByPath.Values); RuntimeTarget=$targetName }
    } finally { $document.Dispose() }
}

function Get-D32PowerShellAuthorityPeImportNames {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    if ($Bytes.Length -lt 2 -or $Bytes[0] -ne 0x4d -or $Bytes[1] -ne 0x5a) { return ,@() }
    if ($Bytes.Length -lt 0x40) { throw 'bounded native resolver image has a truncated DOS header' }
    $peOffset = [BitConverter]::ToInt32($Bytes,0x3c)
    if ($peOffset -lt 0x40 -or $peOffset -gt ($Bytes.Length - 24) -or
        $Bytes[$peOffset] -ne 0x50 -or $Bytes[$peOffset + 1] -ne 0x45 -or $Bytes[$peOffset + 2] -ne 0 -or $Bytes[$peOffset + 3] -ne 0) {
        throw 'bounded native resolver image has an invalid PE signature/offset'
    }
    $sectionCount = [BitConverter]::ToUInt16($Bytes,$peOffset + 6)
    $optionalSize = [BitConverter]::ToUInt16($Bytes,$peOffset + 20)
    $optionalOffset = $peOffset + 24
    if ($sectionCount -lt 1 -or $sectionCount -gt 96 -or $optionalSize -lt 96 -or $optionalOffset -gt ($Bytes.Length - $optionalSize)) {
        throw 'bounded native resolver image has invalid section/optional-header bounds'
    }
    $magic = [BitConverter]::ToUInt16($Bytes,$optionalOffset)
    $directoryOffset = if ($magic -eq 0x10b) { $optionalOffset + 96 } elseif ($magic -eq 0x20b) { $optionalOffset + 112 } else { throw 'bounded native resolver image has an unsupported PE optional-header format' }
    if ($directoryOffset + (14 * 8) -gt ($optionalOffset + $optionalSize)) { throw 'bounded native resolver image omits bounded import directories' }
    $sectionOffset = $optionalOffset + $optionalSize
    if ($sectionOffset -gt ($Bytes.Length - ([int]$sectionCount * 40))) { throw 'bounded native resolver image section table exceeds file bounds' }
    $sections = [System.Collections.Generic.List[object]]::new()
    for ($index=0; $index -lt $sectionCount; $index++) {
        $offset = $sectionOffset + ($index * 40)
        $sections.Add([PSCustomObject]@{ virtual_size=[BitConverter]::ToUInt32($Bytes,$offset + 8); virtual_address=[BitConverter]::ToUInt32($Bytes,$offset + 12)
            raw_size=[BitConverter]::ToUInt32($Bytes,$offset + 16); raw_pointer=[BitConverter]::ToUInt32($Bytes,$offset + 20) })
    }
    $sizeOfHeaders = [BitConverter]::ToUInt32($Bytes,$optionalOffset + 60)
    $mapRva = {
        param([UInt32]$Rva)
        if ($Rva -lt $sizeOfHeaders -and $Rva -lt $Bytes.Length) { return [int]$Rva }
        foreach ($section in $sections) {
            $span = [Math]::Max([UInt64]$section.virtual_size,[UInt64]$section.raw_size)
            if ([UInt64]$Rva -lt [UInt64]$section.virtual_address -or [UInt64]$Rva -ge ([UInt64]$section.virtual_address + $span)) { continue }
            $delta = [UInt64]$Rva - [UInt64]$section.virtual_address
            if ($delta -ge [UInt64]$section.raw_size) { throw 'bounded native resolver RVA maps to an unbacked virtual section' }
            $fileOffset = [UInt64]$section.raw_pointer + $delta
            if ($fileOffset -ge [UInt64]$Bytes.Length) { throw 'bounded native resolver RVA maps beyond file bounds' }
            return [int]$fileOffset
        }
        throw 'bounded native resolver RVA has no exact file-backed section'
    }
    $names = [System.Collections.Generic.SortedSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($directoryIndex in @(1,13)) {
        $directoryOffsetForKind = $directoryOffset + ($directoryIndex * 8)
        $rva = [BitConverter]::ToUInt32($Bytes,$directoryOffsetForKind)
        $size = [BitConverter]::ToUInt32($Bytes,$directoryOffsetForKind + 4)
        if ($rva -eq 0 -and $size -eq 0) { continue }
        if ($rva -eq 0 -or $size -eq 0) { throw 'bounded native resolver import directory is partially empty' }
        $tableOffset = & $mapRva $rva
        $stride = if ($directoryIndex -eq 1) { 20 } else { 32 }
        $maximumRecords = [Math]::Min(1024,[int][Math]::Floor([double]$size / $stride))
        if ($maximumRecords -le 0) { throw 'bounded native resolver import directory has no complete descriptor' }
        $terminated = $false
        for ($descriptorIndex=0; $descriptorIndex -lt $maximumRecords; $descriptorIndex++) {
            $descriptor = $tableOffset + ($descriptorIndex * $stride)
            if ($descriptor + $stride -gt $Bytes.Length) { throw 'bounded native resolver import descriptor exceeds file bounds' }
            if ($directoryIndex -eq 1) { $nameRva = [BitConverter]::ToUInt32($Bytes,$descriptor + 12) }
            else {
                $attributes = [BitConverter]::ToUInt32($Bytes,$descriptor)
                if (($attributes -band 1) -eq 0) { throw 'bounded native resolver delay import uses unsupported VA-based naming' }
                $nameRva = [BitConverter]::ToUInt32($Bytes,$descriptor + 4)
            }
            if ($nameRva -eq 0) { $terminated = $true; break }
            $nameOffset = & $mapRva $nameRva
            $end = $nameOffset
            while ($end -lt $Bytes.Length -and $end -lt ($nameOffset + 260) -and $Bytes[$end] -ne 0) { $end++ }
            if ($end -ge $Bytes.Length -or $end -eq $nameOffset -or $end -ge ($nameOffset + 260)) { throw 'bounded native resolver import name is empty, unterminated, or overlong' }
            $name = [Text.Encoding]::ASCII.GetString($Bytes,$nameOffset,$end - $nameOffset)
            if ($name -cnotmatch '^[A-Za-z0-9_.-]{1,128}\.dll$') { throw "bounded native resolver import name is not a basename DLL: $name" }
            [void]$names.Add($name)
        }
        if (-not $terminated) { throw 'bounded native resolver import descriptors exceed the 1024-entry/table bound' }
    }
    return ,([string[]]$names)
}

function Assert-D32PowerShellAuthorityStaticRuntimeConfig {
    param([Parameter(Mandatory = $true)][byte[]]$RuntimeConfigBytes, [Parameter(Mandatory = $true)][string]$RuntimeTarget)
    if ($RuntimeConfigBytes.Length -le 0 -or $RuntimeConfigBytes.Length -gt 4194304) { throw 'fixed pwsh.runtimeconfig.json content is empty or exceeds its 4 MiB limit' }
    $document = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false,$true).GetString($RuntimeConfigBytes))
    try {
        if ($document.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
            (Test-D32PowerShellAuthorityJsonDuplicates -Element $document.RootElement)) { throw 'fixed pwsh.runtimeconfig.json is not a duplicate-free JSON object' }
        $runtimeOptions = $document.RootElement.GetProperty('runtimeOptions')
        if ($runtimeOptions.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { throw 'fixed pwsh.runtimeconfig.json runtimeOptions is not an object' }
        foreach ($property in $document.RootElement.EnumerateObject()) {
            if ($property.Name -cne 'runtimeOptions') { throw "fixed pwsh.runtimeconfig.json has an unsupported root role: $($property.Name)" }
        }
        $allowed = @('tfm','configProperties')
        foreach ($property in $runtimeOptions.EnumerateObject()) {
            if ($property.Name -cnotin $allowed) { throw "fixed pwsh.runtimeconfig.json contains an unclassified runtime option: $($property.Name)" }
        }
        $runtimeTargetMatch = [Regex]::Match($RuntimeTarget,'^\.NETCoreApp,Version=v(?<major>\d+)\.(?<minor>\d+)(?:/(?<rid>[A-Za-z0-9_.-]{1,128}))?$')
        if (-not $runtimeTargetMatch.Success) { throw 'fixed pwsh.deps.json runtime target is not one bounded .NETCoreApp target' }
        $tfm = [System.Text.Json.JsonElement]::new()
        if (-not $runtimeOptions.TryGetProperty('tfm',[ref]$tfm) -or $tfm.ValueKind -ne [System.Text.Json.JsonValueKind]::String -or
            [string]$tfm.GetString() -cne ('net' + $runtimeTargetMatch.Groups['major'].Value + '.' + $runtimeTargetMatch.Groups['minor'].Value)) {
            throw 'fixed pwsh.runtimeconfig.json TFM is missing or differs from the exact deps target'
        }
        $configProperties = [System.Text.Json.JsonElement]::new()
        if ($runtimeOptions.TryGetProperty('configProperties',[ref]$configProperties)) {
            if ($configProperties.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { throw 'fixed pwsh.runtimeconfig.json configProperties is not an object' }
            foreach ($property in $configProperties.EnumerateObject()) {
                if ($property.Value.ValueKind -notin @([System.Text.Json.JsonValueKind]::True,[System.Text.Json.JsonValueKind]::False,[System.Text.Json.JsonValueKind]::Number)) {
                    throw "fixed pwsh.runtimeconfig.json configProperty is not a bounded scalar resolver-neutral value: $($property.Name)"
                }
            }
        }
        foreach ($externalRoot in @('framework','frameworks','includedFrameworks')) {
            $externalRootElement = [System.Text.Json.JsonElement]::new()
            if ($runtimeOptions.TryGetProperty($externalRoot,[ref]$externalRootElement)) {
                throw "fixed pwsh.runtimeconfig.json selects a framework root outside the exact V2 PowerShell/Windows candidate domains: $externalRoot"
            }
        }
        return $true
    } finally { $document.Dispose() }
}

function Get-D32PowerShellAuthorityStaticWindowsNativeFiles {
    param(
        [Parameter(Mandatory = $true)][string]$PowerShellRoot,
        [Parameter(Mandatory = $true)][string]$SystemRoot,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$RuntimeFiles,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$NativeAssetFiles,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$DirectoryFences,
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[object]]$OpenFiles
    )
    $fixedPowerShellRoot = [IO.Path]::GetFullPath($PowerShellRoot)
    $windowsRoot = [IO.Path]::GetFullPath((Get-D32PowerShellAuthorityWindowsRootPath))
    $systemRootFull = [IO.Path]::GetFullPath($SystemRoot)
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($windowsRoot,$systemRootFull)) { throw 'static Windows root does not equal the GetWindowsDirectoryW opened namespace' }
    $system32 = [IO.Path]::GetFullPath([IO.Path]::Combine($windowsRoot,'System32'))
    Add-D32PowerShellAuthorityDirectoryChain -Directory $windowsRoot -Fences $DirectoryFences
    Add-D32PowerShellAuthorityDirectoryChain -Directory $system32 -Fences $DirectoryFences
    $runtimeByName = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($file in $RuntimeFiles) {
        Assert-D32PowerShellAuthorityPreparationDeadline
        $filePath = [string]$file.Record.path
        if (-not (Test-D32PowerShellAuthorityPathWithin -Child $filePath -Parent $fixedPowerShellRoot)) { continue }
        $leaf = [IO.Path]::GetFileName($filePath)
        if ([StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName($filePath),$fixedPowerShellRoot) -and -not $runtimeByName.ContainsKey($leaf)) { $runtimeByName.Add($leaf,$file) }
    }
    $pending = [System.Collections.Generic.Stack[object]]::new()
    foreach ($file in $RuntimeFiles) { if ([IO.Path]::GetExtension([string]$file.Record.path) -iin @('.dll','.exe')) { $pending.Push($file) } }
    foreach ($file in $NativeAssetFiles) { $pending.Push($file) }
    $visitedRuntime = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $windowsFiles = [System.Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    $totalBytes = [decimal]0
    $parsedCount = 0
    while ($pending.Count -gt 0) {
        Assert-D32PowerShellAuthorityPreparationDeadline
        $current = $pending.Pop()
        $currentPath = [string]$current.Record.path
        if (-not $visitedRuntime.Add($currentPath)) { continue }
        if (++$parsedCount -gt 4096) { throw 'static native dependency roots exceed the fixed 4096 image bound' }
        $imports = Get-D32PowerShellAuthorityPeImportNames -Bytes ([byte[]]$current.Bytes)
        foreach ($importName in $imports) {
            Assert-D32PowerShellAuthorityPreparationDeadline
            if ($importName -match '^(?i:api-ms-win-|ext-ms-win-)') { continue }
            if ($runtimeByName.ContainsKey([string]$importName)) { $pending.Push($runtimeByName[[string]$importName]); continue }
            $importPath = [IO.Path]::GetFullPath([IO.Path]::Combine($system32,[string]$importName))
            if (-not (Test-D32PowerShellAuthorityPathWithin -Child $importPath -Parent $system32)) { throw "static Windows import escapes System32: $importName" }
            if (-not $windowsFiles.ContainsKey($importPath)) {
                if ($windowsFiles.Count -ge 4096) { throw 'static Windows native dependency closure exceeds the fixed 4096-file bound' }
                $snapshot = Open-D32PowerShellAuthorityFile -Path $importPath -DirectoryFences $DirectoryFences -MaximumBytes 268435456L
                $OpenFiles.Add($snapshot)
                if (-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $snapshot.Security -IsDirectory:$false)) { throw "static Windows native dependency is not in a protected namespace: $importPath" }
                $windowsFiles.Add($importPath,$snapshot)
                $totalBytes += [decimal]$snapshot.Record.bytes
                if ($totalBytes -gt [decimal]2147483648) { throw 'static Windows native dependency closure exceeds the fixed 2 GiB aggregate bound' }
                $pending.Push($snapshot)
            }
        }
    }
    if ($windowsFiles.Count -lt 1) { throw 'static PowerShell image import closure contains no fixed Windows native references' }
    return ,@($windowsFiles.Values)
}

function New-D32PowerShellAuthorityStaticWindowsComponent {
    param(
        [Parameter(Mandatory = $true)][string]$SystemRoot,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$NativeFiles,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$TrustedPlatformAssemblyReferences,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$DirectoryFences,
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[object]]$OpenFiles
    )
    $windowsRoot = [IO.Path]::GetFullPath((Get-D32PowerShellAuthorityWindowsRootPath))
    $systemRootFull = [IO.Path]::GetFullPath($SystemRoot)
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($windowsRoot,$systemRootFull)) { throw 'static Windows component root differs from the opened GetWindowsDirectoryW namespace' }
    Add-D32PowerShellAuthorityDirectoryChain -Directory $windowsRoot -Fences $DirectoryFences
    $fileByPath = [System.Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($snapshot in $NativeFiles) {
        Assert-D32PowerShellAuthorityPreparationDeadline
        $path = [IO.Path]::GetFullPath([string]$snapshot.Record.path)
        if (-not (Test-D32PowerShellAuthorityPathWithin -Child $path -Parent $windowsRoot)) { throw "static Windows native image escapes the verified OS root: $path" }
        if (-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $snapshot.Security -IsDirectory:$false)) { throw "static Windows native image has an unprotected namespace: $path" }
        if (-not $fileByPath.ContainsKey($path)) { $fileByPath.Add($path,$snapshot) }
        Add-D32PowerShellAuthorityDirectoryChain -Directory ([IO.Path]::GetDirectoryName($path)) -Fences $DirectoryFences
    }
    foreach ($reference in $TrustedPlatformAssemblyReferences) {
        Assert-D32PowerShellAuthorityPreparationDeadline
        $path = [IO.Path]::GetFullPath([string]$reference.path)
        if (-not (Test-D32PowerShellAuthorityPathWithin -Child $path -Parent $windowsRoot)) { continue }
        if (-not $fileByPath.ContainsKey($path)) {
            $snapshot = Open-D32PowerShellAuthorityFile -Path $path -DirectoryFences $DirectoryFences -MaximumBytes 268435456L
            $OpenFiles.Add($snapshot)
            if (-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $snapshot.Security -IsDirectory:$false)) { throw "static Windows TPA image has an unprotected namespace: $path" }
            if ([string]$snapshot.Record.sha256 -cne [string]$reference.sha256 -or [Int64]$snapshot.Record.bytes -ne [Int64]$reference.bytes -or
                [string]$snapshot.Record.volume_serial_hex -cne [string]$reference.volume_serial_hex -or [string]$snapshot.Record.file_id_hex -cne [string]$reference.file_id_hex) {
                throw "static Windows TPA reference differs from its independently opened file identity: $path"
            }
            $fileByPath.Add($path,$snapshot)
        }
        Add-D32PowerShellAuthorityDirectoryChain -Directory ([IO.Path]::GetDirectoryName($path)) -Fences $DirectoryFences
    }
    if ($fileByPath.Count -lt 1 -or $fileByPath.Count -gt 4096) { throw 'static Windows component file list is empty or exceeds 4096 entries' }

    $directoryByPath = [System.Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    $ancestorByPath = [System.Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($fence in $DirectoryFences.Values) {
        Assert-D32PowerShellAuthorityPreparationDeadline
        $path = [IO.Path]::GetFullPath([string]$fence.Path)
        $inside = Test-D32PowerShellAuthorityPathWithin -Child $path -Parent $windowsRoot
        $isAncestor = -not $inside -and (Test-D32PowerShellAuthorityPathWithin -Child $windowsRoot -Parent $path)
        if (-not ($inside -or $isAncestor)) { continue }
        $identity = Get-D32PowerShellAuthorityHandleIdentity -Handle $fence.Handle
        $security = [PSCustomObject]@{Path=[string]$fence.Path;OwnerSid=[string]$fence.OwnerSid;Sddl=[string]$fence.Sddl;AclSha256=[string]$fence.AclSha256;Security=$fence.Security}
        if (($identity.Attributes -band [int][IO.FileAttributes]::Directory) -eq 0 -or ($identity.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals((Get-D32PowerShellAuthorityFinalHandlePath -Handle $fence.Handle),$path) -or
            -not (Test-D32PowerShellAuthorityProtectedSecurity -Security $security -IsDirectory:$true -IsProtectedAncestor:$isAncestor)) {
            throw "static Windows component directory is not protected or its identity changed: $path"
        }
        $record = [ordered]@{kind=$(if ($isAncestor) {'ancestor'} else {'directory'});path=[string]$fence.Path
            volume_serial_hex=[string]$identity.VolumeSerialHex;file_id_hex=[string]$identity.FileIdHex;owner_sid=[string]$fence.OwnerSid
            security_descriptor_sddl=[string]$fence.Sddl;security_descriptor_sha256=[string]$fence.AclSha256}
        if ($inside) { $directoryByPath[$path] = $record } else { $ancestorByPath[$path] = $record }
    }
    if (-not $directoryByPath.ContainsKey($windowsRoot) -or $directoryByPath.Count -gt 1024 -or $ancestorByPath.Count -gt 1024) {
        throw 'static Windows component root/directory/ancestor inventory is absent or exceeds its fixed bound'
    }
    $directories = @($directoryByPath.Values)
    $files = [System.Collections.Generic.List[object]]::new()
    [decimal]$aggregateBytes = 0
    foreach ($snapshot in $fileByPath.Values) {
        $record = [ordered]@{kind='file';path=[string]$snapshot.Record.path;bytes=[Int64]$snapshot.Record.bytes;sha256=[string]$snapshot.Record.sha256
            volume_serial_hex=[string]$snapshot.Record.volume_serial_hex;file_id_hex=[string]$snapshot.Record.file_id_hex
            owner_sid=[string]$snapshot.Security.OwnerSid;security_descriptor_sddl=[string]$snapshot.Security.Sddl;security_descriptor_sha256=[string]$snapshot.Security.AclSha256}
        $files.Add($record); $aggregateBytes += [decimal]$record.bytes
    }
    if ($aggregateBytes -gt [decimal]2147483648) { throw 'static Windows component exceeds the fixed 2 GiB aggregate bound' }
    $distribution = [ordered]@{root_path=$windowsRoot;inventory_sha256='';directories=$directories;files=$files.ToArray()
        protected_ancestors=@($ancestorByPath.Values);trusted_writer_sids=@('S-1-5-18','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464','S-1-5-32-544')}
    $distribution.inventory_sha256 = Get-D32PowerShellAuthorityRuntimeInventoryDigest -Directories $distribution.directories -Files $distribution.files -Ancestors $distribution.protected_ancestors
    $sourceProof = [ordered]@{proof_type='GET_WINDOWSDIRECTORYW_OPENED_NAMESPACE_V1';api_path=$windowsRoot;environment_system_root=$systemRootFull;os_version=[Environment]::OSVersion.VersionString}
    $componentDigestMaterial = [string]$distribution.inventory_sha256 + "`n" + (ConvertTo-D32PowerShellAuthorityJsonText -Value $sourceProof) + "`n"
    $componentDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes($componentDigestMaterial))).ToLowerInvariant()
    $rootKey = $windowsRoot.TrimEnd([char[]]@('\\','/')); if ($rootKey.Length -eq 2 -and $rootKey[1] -eq ':') { $rootKey += [IO.Path]::DirectorySeparatorChar }
    $rootFence = $DirectoryFences[$rootKey]
    if ($null -eq $rootFence) { throw 'static Windows component root identity fence is missing' }
    return [ordered]@{component_type='MICROSOFT_WINDOWS_OS_INSTALLATION';version=[Environment]::OSVersion.VersionString;root_path=$windowsRoot
        root_volume_serial_hex=[string]$rootFence.VolumeSerialHex;root_file_id_hex=[string]$rootFence.FileIdHex;inventory_sha256=$componentDigest
        source_proof=$sourceProof;distribution=$distribution;native_files=$files.ToArray()}
}

function New-D32PowerShellAuthorityStaticDefenderComponent {
    param(
        [Parameter(Mandatory = $true)][string]$RootPath,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$DirectoryFences,
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[object]]$OpenFiles
    )
    $root = [IO.Path]::GetFullPath($RootPath)
    $distribution = Get-D32PowerShellAuthorityDefenderPlatformSnapshot -RootPath $root -DirectoryFences $DirectoryFences -OpenFiles $OpenFiles `
        -MaximumFiles 4096 -MaximumDirectories 1024 -MaximumAggregateBytes 2147483648L -MaximumSingleFileBytes 268435456L
    $anchors = [System.Collections.Generic.List[object]]::new()
    $nativeFiles = [System.Collections.Generic.List[object]]::new()
    $expectedAnchors = @('MpOav.dll','MPCLIENT.DLL')
    $productVersion = [IO.Path]::GetFileName($root)
    $productVersion = $productVersion.Substring(0,$productVersion.LastIndexOf('-'))
    foreach ($anchor in $expectedAnchors) {
        Assert-D32PowerShellAuthorityPreparationDeadline
        $matches = @($distribution.files | Where-Object { [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFileName([string]$_.path),$anchor) })
        if ($matches.Count -ne 1) { throw "fixed Defender package lacks exactly one required static anchor: $anchor" }
        $fileRecord = $matches[0]
        $snapshot = $null
        foreach ($openedFile in $OpenFiles) { if ([StringComparer]::OrdinalIgnoreCase.Equals([string]$openedFile.Record.path,[string]$fileRecord.path)) { $snapshot = $openedFile; break } }
        if ($null -eq $snapshot) { throw "fixed Defender anchor lacks its retained V2 opened content: $anchor" }
        $proof = Get-D32PowerShellAuthorityAuthenticodeSourceProof -Path ([string]$fileRecord.path)
        if ([string]$proof.product_version -cne $productVersion) { throw "fixed Defender anchor product version differs from its exact versioned package: $anchor" }
        $nativeFiles.Add($fileRecord)
        $anchors.Add([ordered]@{file=[ordered]@{path=[string]$fileRecord.path;bytes=[Int64]$fileRecord.bytes;sha256=[string]$fileRecord.sha256
            volume_serial_hex=[string]$fileRecord.volume_serial_hex;file_id_hex=[string]$fileRecord.file_id_hex};source_proof=$proof})
    }
    $sourceProof = [ordered]@{proof_type='WINTRUST_CACHE_ONLY_AUTHENTICODE_V1';status='VERIFIED';anchor_images=$anchors.ToArray()}
    $digestMaterial = [string]$distribution.inventory_sha256 + "`n" + (ConvertTo-D32PowerShellAuthorityJsonText -Value $anchors.ToArray()) + "`n"
    $componentDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes($digestMaterial))).ToLowerInvariant()
    $rootKey = $root.TrimEnd([char[]]@('\\','/')); if ($rootKey.Length -eq 2 -and $rootKey[1] -eq ':') { $rootKey += [IO.Path]::DirectorySeparatorChar }
    $rootFence = $DirectoryFences[$rootKey]
    if ($null -eq $rootFence) { throw 'fixed Defender package root identity fence is missing' }
    return [ordered]@{component_type='MICROSOFT_WINDOWS_DEFENDER_PLATFORM';version=[IO.Path]::GetFileName($root);root_path=$root
        root_volume_serial_hex=[string]$rootFence.VolumeSerialHex;root_file_id_hex=[string]$rootFence.FileIdHex;inventory_sha256=$componentDigest
        source_proof=$sourceProof;distribution=$distribution;native_files=$nativeFiles.ToArray()}
}

function New-D32PowerShellAuthorityNonSourceL1RuntimeContentCandidate {
    param([Parameter(Mandatory = $true)][string]$CandidateSha, [long]$DeadlineTicks = 0)
    $repository = [IO.Path]::GetFullPath([IO.Path]::Combine($PSScriptRoot,'..'))
    $runtimeHome = [IO.Path]::GetFullPath([IO.Path]::Combine([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles),'PowerShell','7'))
    $runtimePath = [IO.Path]::GetFullPath([IO.Path]::Combine($runtimeHome,'pwsh.exe'))
    $windowsApiRoot = [IO.Path]::GetFullPath((Get-D32PowerShellAuthorityWindowsRootPath))
    $systemRoot = [IO.Path]::GetFullPath([string]$env:SystemRoot)
    $fences = [System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)
    $opened = [System.Collections.Generic.List[object]]::new()
    $previousFences = $script:D32PowerShellAdmissionDirectoryFences
    $previousTrustedRuntimeRoot = $script:D32PowerShellAuthorityTrustedRuntimeRoot
    $previousPreparationDeadline = $script:D32PowerShellAuthorityPreparationDeadlineTicks
    $script:D32PowerShellAdmissionDirectoryFences = $fences
    $script:D32PowerShellAuthorityTrustedRuntimeRoot = $runtimeHome
    if ($DeadlineTicks -gt 0) { $script:D32PowerShellAuthorityPreparationDeadlineTicks = $DeadlineTicks }
    $gaps = [System.Collections.Generic.List[string]]::new()
    try {
        Assert-D32PowerShellAuthorityPreparationDeadline
        if ($CandidateSha -cnotmatch '^[0-9a-f]{40}$' -or $runtimeHome -cnotmatch '^[A-Za-z]:\\Program Files\\PowerShell\\7$') {
            $gaps.Add('candidate SHA or fixed Program Files PowerShell 7 root is not canonical')
            return [PSCustomObject][ordered]@{gate_authority='NONE';status='BLOCKED_INPUT_GAPS';candidate=$null;candidate_json=$null;candidate_sha256=$null;gaps=@($gaps.ToArray())}
        }
        if (-not [StringComparer]::OrdinalIgnoreCase.Equals($windowsApiRoot,$systemRoot)) { throw 'GetWindowsDirectoryW does not match the fixed process SystemRoot namespace' }
        Add-D32PowerShellAuthorityDirectoryChain -Directory $repository -Fences $fences
        $repositoryKey = $repository.TrimEnd([char[]]@('\\','/'))
        if ($repositoryKey.Length -eq 2 -and $repositoryKey[1] -eq ':') { $repositoryKey += [IO.Path]::DirectorySeparatorChar }
        $repositoryFence = $fences[$repositoryKey]
        if ($null -eq $repositoryFence) { throw 'fixed source repository V2 identity fence is missing' }
        $repositoryIdentity = [PSCustomObject][ordered]@{VolumeSerialHex=[string]$repositoryFence.VolumeSerialHex;FileIdHex=[string]$repositoryFence.FileIdHex}
        $runtimeFiles = [System.Collections.Generic.List[object]]::new()
        $distribution = Get-D32PowerShellAuthorityRuntimeDistributionSnapshot -PowerShellRoot $runtimeHome -DirectoryFences $fences -OpenFiles $runtimeFiles `
            -MaximumFiles 4096 -MaximumDirectories 1024 -MaximumAggregateBytes 2147483648L -MaximumSingleFileBytes 268435456L
        foreach ($file in $runtimeFiles) { Assert-D32PowerShellAuthorityPreparationDeadline; $opened.Add($file) }
        $runtimeOpened = Open-D32PowerShellAuthorityFile -Path $runtimePath -DirectoryFences $fences -MaximumBytes 268435456L
        $opened.Add($runtimeOpened)

        $utilityRole = $null
        foreach ($role in (Get-D32PowerShellAuthorityFixedModuleRoles -PowerShellRoot $runtimeHome)) {
            Assert-D32PowerShellAuthorityPreparationDeadline
            if ([string]$role.Name -ceq 'Microsoft.PowerShell.Utility') { $utilityRole = $role; break }
        }
        if ($null -eq $utilityRole) { throw 'fixed Utility role is not defined by V2 module authority' }
        $expectedUtility = Get-D32PowerShellAuthorityExpectedModuleFiles -PowerShellRoot $runtimeHome -Role $utilityRole
        if ($null -ne $expectedUtility.Manifest -and $null -ne $expectedUtility.Manifest.Stream) { $opened.Add($expectedUtility.Manifest) }
        $utilityRecords = [System.Collections.Generic.List[object]]::new()
        foreach ($path in $expectedUtility.Paths) {
            Assert-D32PowerShellAuthorityPreparationDeadline
            if ([StringComparer]::OrdinalIgnoreCase.Equals([string]$path,[string]$expectedUtility.Manifest.Record.path)) {
                $utilityRecords.Add($expectedUtility.Manifest.Record)
            } else {
                if ($utilityRecords.Count -ge 4096) { throw 'fixed Utility content closure exceeds its bounded file count' }
                $utilityFile = Open-D32PowerShellAuthorityFile -Path ([string]$path) -DirectoryFences $fences -MaximumBytes 268435456L
                $opened.Add($utilityFile); $utilityRecords.Add($utilityFile.Record)
            }
        }
        $startupBytesByRole = [System.Collections.Generic.Dictionary[string,byte[]]]::new([StringComparer]::Ordinal)
        $startup = [ordered]@{}
        foreach ($input in @(@('deps','pwsh.deps.json'),@('runtime_config','pwsh.runtimeconfig.json'),@('protected_startup_config','powershell.config.json'))) {
            Assert-D32PowerShellAuthorityPreparationDeadline
            $name=[string]$input[0]; $path=[IO.Path]::GetFullPath([IO.Path]::Combine($runtimeHome,[string]$input[1]))
            if ([IO.File]::Exists($path)) {
                $file=Open-D32PowerShellAuthorityFile -Path $path -DirectoryFences $fences -MaximumBytes 4194304L
                $opened.Add($file)
                $startupBytesByRole.Add($name,[byte[]]$file.Bytes)
                $startup[$name]=[PSCustomObject][ordered]@{state='PRESENT';reference=[PSCustomObject][ordered]@{path=[string]$file.Record.path
                    bytes=[Int64]$file.Record.bytes;sha256=[string]$file.Record.sha256;volume_serial_hex=[string]$file.Record.volume_serial_hex
                    file_id_hex=[string]$file.Record.file_id_hex};absence_witness_sha256=$null}
            } elseif ([IO.Directory]::Exists($path)) {
                throw ('fixed runtime startup role exists as a directory: ' + $name)
            } else {
                $parentPath=[IO.Path]::GetDirectoryName($path); $parentRecord=$null
                foreach ($directory in @($distribution.directories)) {
                    if ([StringComparer]::OrdinalIgnoreCase.Equals([string]$directory.path,$parentPath)) { $parentRecord=$directory; break }
                }
                if ($null -eq $parentRecord -or -not (Test-D32PowerShellAuthorityPathNoReparse -Path $parentPath)) {
                    throw ('fixed runtime startup absence lacks a protected V2 parent directory: ' + $name)
                }
                $startup[$name]=[PSCustomObject][ordered]@{state='PROTECTED_ABSENT';reference=$null
                    absence_witness_sha256=(Get-D32PowerShellAuthorityProtectedAbsenceWitnessSha256 -RolePath $path -ParentDirectoryRecord $parentRecord)}
            }
        }
        $startupStates=[PSCustomObject][ordered]@{deps=$startup.deps;runtime_config=$startup.runtime_config;protected_startup_config=$startup.protected_startup_config}
        $runtimeReference=[PSCustomObject][ordered]@{path=[string]$runtimeOpened.Record.path;bytes=[Int64]$runtimeOpened.Record.bytes
            sha256=[string]$runtimeOpened.Record.sha256;volume_serial_hex=[string]$runtimeOpened.Record.volume_serial_hex;file_id_hex=[string]$runtimeOpened.Record.file_id_hex}
        if (-not $startupBytesByRole.ContainsKey('deps') -or -not $startupBytesByRole.ContainsKey('runtime_config')) {
            throw 'fixed pwsh.deps.json and pwsh.runtimeconfig.json content are both required to resolve the target runtime without child execution'
        }
        $staticAssets = Get-D32PowerShellAuthorityNonSourceL1StaticRuntimeAssets -DepsBytes $startupBytesByRole['deps'] `
            -PowerShellRoot $runtimeHome -DistributionFiles @($distribution.files)
        [void](Assert-D32PowerShellAuthorityStaticRuntimeConfig -RuntimeConfigBytes $startupBytesByRole['runtime_config'] -RuntimeTarget ([string]$staticAssets.RuntimeTarget))
        $nativeAssetPathSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($file in $staticAssets.NativeAssetFiles) { [void]$nativeAssetPathSet.Add([string]$file.path) }
        $nativeAssetSnapshots = [System.Collections.Generic.List[object]]::new()
        foreach ($file in $runtimeFiles) { if ($nativeAssetPathSet.Contains([string]$file.Record.path)) { $nativeAssetSnapshots.Add($file) } }
        Assert-D32PowerShellAuthorityPreparationDeadline
        if ($nativeAssetSnapshots.Count -ne $staticAssets.NativeAssetFiles.Count) { throw 'fixed pwsh.deps.json native assets do not all have their independently opened V2 file snapshots' }
        $windowsNativeFiles = Get-D32PowerShellAuthorityStaticWindowsNativeFiles -PowerShellRoot $runtimeHome -SystemRoot $systemRoot `
            -RuntimeFiles $runtimeFiles.ToArray() -NativeAssetFiles $nativeAssetSnapshots.ToArray() -DirectoryFences $fences -OpenFiles $opened
        $windowsComponent = New-D32PowerShellAuthorityStaticWindowsComponent -SystemRoot $systemRoot -NativeFiles $windowsNativeFiles `
            -TrustedPlatformAssemblyReferences $staticAssets.TrustedPlatformAssemblyReferences -DirectoryFences $fences -OpenFiles $opened

        $defenderParent = 'C:\ProgramData\Microsoft\Windows Defender\Platform'
        if (-not [IO.Directory]::Exists($defenderParent)) { throw 'fixed protected Defender Platform parent is unavailable' }
        Add-D32PowerShellAuthorityDirectoryChain -Directory $defenderParent -Fences $fences
        $defenderVersionRoots = [System.Collections.Generic.List[string]]::new()
        $defenderEntryCount = 0
        foreach ($entry in [IO.Directory]::EnumerateDirectories($defenderParent)) {
            Assert-D32PowerShellAuthorityPreparationDeadline
            if (++$defenderEntryCount -gt 64) { throw 'fixed Defender Platform version-root census exceeds 64 direct entries' }
            $fullEntry = [IO.Path]::GetFullPath([string]$entry)
            if ([IO.Path]::GetFileName($fullEntry) -cmatch '^4\.\d+\.\d+\.\d+-\d+$') { $defenderVersionRoots.Add($fullEntry) }
        }
        if ($defenderVersionRoots.Count -ne 1) { throw 'fixed Defender Platform version root is missing or ambiguous; observer-loaded origins are not used to choose it' }
        $defenderComponent = New-D32PowerShellAuthorityStaticDefenderComponent -RootPath $defenderVersionRoots[0] `
            -DirectoryFences $fences -OpenFiles $opened
        $osSecurityComponents = @($windowsComponent,$defenderComponent)

        $nativeDirectoryByPath = [System.Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
        $fixedNativePaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        [void]$fixedNativePaths.Add($runtimeHome); [void]$fixedNativePaths.Add([IO.Path]::GetFullPath([IO.Path]::Combine($systemRoot,'System32')))
        foreach ($file in $staticAssets.NativeAssetFiles) { [void]$fixedNativePaths.Add([IO.Path]::GetDirectoryName([string]$file.path)) }
        foreach ($nativeDirectory in $fixedNativePaths) {
            Assert-D32PowerShellAuthorityPreparationDeadline
            $record = $null
            foreach ($candidateDirectory in @($distribution.directories)) {
                if ([StringComparer]::OrdinalIgnoreCase.Equals([string]$candidateDirectory.path,[string]$nativeDirectory)) { $record = $candidateDirectory; break }
            }
            if ($null -eq $record) {
                foreach ($candidateDirectory in @($windowsComponent.distribution.directories)) {
                    if ([StringComparer]::OrdinalIgnoreCase.Equals([string]$candidateDirectory.path,[string]$nativeDirectory)) { $record = $candidateDirectory; break }
                }
            }
            if ($null -eq $record -or [string]$record.kind -cne 'directory') { throw "fixed target native-search directory lacks a V2 protected directory identity: $nativeDirectory" }
            if (-not $nativeDirectoryByPath.ContainsKey([string]$record.path)) { $nativeDirectoryByPath.Add([string]$record.path,$record) }
        }
        if ($nativeDirectoryByPath.Count -lt 1 -or $nativeDirectoryByPath.Count -gt 1024) { throw 'fixed target native-search V2 directory list is empty or exceeds 1024 entries' }
        Assert-D32PowerShellAuthorityPreparationDeadline
        return New-D32PowerShellAuthorityNonSourceL1RuntimeContentCandidateFromV2Inputs -CandidateSha $CandidateSha -Repository $repository `
            -RepositoryIdentity $repositoryIdentity -RuntimeFileReference $runtimeReference -PowerShellHome $runtimeHome -SystemRoot $systemRoot `
            -Distribution $distribution -OsSecurityComponents $osSecurityComponents -UtilityManifestReference $expectedUtility.Manifest.Record `
            -UtilityFiles $utilityRecords.ToArray() -StartupFileStates $startupStates `
            -TrustedPlatformAssemblyReferences $staticAssets.TrustedPlatformAssemblyReferences `
            -NativeSearchDirectoryRecords @($nativeDirectoryByPath.Values) -InputGaps $gaps.ToArray()
    } catch {
        $gaps.Add([string]$_.Exception.Message)
        return [PSCustomObject][ordered]@{gate_authority='NONE';status='BLOCKED_INPUT_GAPS';candidate=$null;candidate_json=$null;candidate_sha256=$null;gaps=@($gaps.ToArray())}
    } finally {
        foreach ($item in $opened) { try { if ($null -ne $item.Stream -and -not $item.Stream.SafeFileHandle.IsClosed) { $item.Stream.Dispose() } } catch {} }
        foreach ($fence in $fences.Values) { try { if ($null -ne $fence.Handle -and -not $fence.Handle.IsClosed) { $fence.Handle.Dispose() } } catch {} }
        $script:D32PowerShellAdmissionDirectoryFences = $previousFences
        $script:D32PowerShellAuthorityTrustedRuntimeRoot = $previousTrustedRuntimeRoot
        $script:D32PowerShellAuthorityPreparationDeadlineTicks = $previousPreparationDeadline
    }
}

function Get-D32PowerShellAuthorityDefenderPlatformSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$RootPath,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$DirectoryFences,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$OpenFiles,
        [ValidateRange(1,4096)][int]$MaximumFiles = 4096,
        [ValidateRange(1,1024)][int]$MaximumDirectories = 1024,
        [ValidateRange(1,2147483648)][long]$MaximumAggregateBytes = 2147483648L,
        [ValidateRange(1,268435456)][long]$MaximumSingleFileBytes = 268435456L
    )
    $root = [IO.Path]::GetFullPath($RootPath)
    $platformParent = 'C:\ProgramData\Microsoft\Windows Defender\Platform'
    $leaf = [IO.Path]::GetFileName($root)
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName($root), $platformParent) -or
        $leaf -cnotmatch '^4\.\d+\.\d+\.\d+-\d+$' -or -not (Test-D32PowerShellAuthorityPathNoReparse -Path $root)) {
        throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: Defender platform root is not the exact versioned Windows installation directory'
    }
    Add-D32PowerShellAuthorityDirectoryChain -Directory $root -Fences $DirectoryFences
    $directories = [System.Collections.Generic.List[object]]::new()
    $files = [System.Collections.Generic.List[object]]::new()
    [decimal]$aggregateBytes = 0
    $identitySet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $pending = [System.Collections.Generic.Stack[string]]::new()
    $pending.Push($root)
    while ($pending.Count -gt 0) {
        Assert-D32PowerShellAuthorityPreparationDeadline
        $directory = [IO.Path]::GetFullPath($pending.Pop())
        $key = $directory.TrimEnd([char[]]@('\','/'))
        if ($key.Length -eq 2 -and $key[1] -eq ':') { $key += [IO.Path]::DirectorySeparatorChar }
        $fence = $DirectoryFences[$key]
        if ($null -eq $fence -or -not $identitySet.Add(([string]$fence.VolumeSerialHex + ':' + [string]$fence.FileIdHex))) {
            throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: Defender distribution directory is missing or aliased: $directory"
        }
        $security = [PSCustomObject]@{ Path = [string]$fence.Path; OwnerSid = [string]$fence.OwnerSid; Sddl = [string]$fence.Sddl; AclSha256 = [string]$fence.AclSha256; Security = $fence.Security }
        $programData = [StringComparer]::OrdinalIgnoreCase.Equals([string]$fence.Path, 'C:\ProgramData')
        $isAncestor = -not [StringComparer]::OrdinalIgnoreCase.Equals([string]$fence.Path, $root) -and
            (Test-D32PowerShellAuthorityPathWithin -Child $root -Parent ([string]$fence.Path))
        if (-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $security -IsDirectory:$true -IsProtectedAncestor:$isAncestor -IsProgramDataAncestor:$programData)) {
            throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: Defender namespace owner/ACL is not protected: $($fence.Path)"
        }
        if ($directories.Count -ge $MaximumDirectories) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: bounded Defender directory count exceeded before opening another entry' }
        $directories.Add([ordered]@{ kind = 'directory'; path = [string]$fence.Path; volume_serial_hex = [string]$fence.VolumeSerialHex; file_id_hex = [string]$fence.FileIdHex; owner_sid = [string]$fence.OwnerSid; security_descriptor_sddl = [string]$fence.Sddl; security_descriptor_sha256 = [string]$fence.AclSha256 })
        $entries = [System.Collections.Generic.List[string]]::new()
        foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($directory)) {
            Assert-D32PowerShellAuthorityPreparationDeadline
            if (($directories.Count + $files.Count + $entries.Count) -ge ($MaximumFiles + $MaximumDirectories)) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: bounded Defender directory-entry enumeration exceeded its fixed ceiling' }
            $entries.Add([IO.Path]::GetFullPath([string]$entry))
        }
        $entryArray = $entries.ToArray()
        [Array]::Sort($entryArray, [StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $entryArray) {
            Assert-D32PowerShellAuthorityPreparationDeadline
            if (([IO.File]::GetAttributes($entry) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: Defender platform contains a reparse entry: $entry" }
            if (([IO.File]::GetAttributes($entry) -band [IO.FileAttributes]::Directory) -ne 0) {
                Add-D32PowerShellAuthorityDirectoryChain -Directory $entry -Fences $DirectoryFences
                $pending.Push($entry)
                continue
            }
            if ($files.Count -ge $MaximumFiles) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: bounded Defender file count exceeded before opening another file' }
            $length = [Int64]([IO.FileInfo]::new($entry)).Length
            if ($length -gt $MaximumSingleFileBytes) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: bounded Defender single-file content limit exceeded before open' }
            if ($aggregateBytes + [decimal]$length -gt [decimal]$MaximumAggregateBytes) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: bounded Defender aggregate content limit exceeded before open' }
            $snapshot = Open-D32PowerShellAuthorityFile -Path $entry -DirectoryFences $DirectoryFences -MaximumBytes $MaximumSingleFileBytes
            $OpenFiles.Add($snapshot)
            if (-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $snapshot.Security -IsDirectory:$false)) {
                throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: Defender platform file has an untrusted writer: $entry"
            }
            $id = [string]$snapshot.Record.volume_serial_hex + ':' + [string]$snapshot.Record.file_id_hex
            if (-not $identitySet.Add($id)) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: Defender platform has aliased file identity: $entry" }
            $aggregateBytes += [decimal]$snapshot.Record.bytes
            if ($aggregateBytes -gt [decimal]$MaximumAggregateBytes) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: bounded Defender aggregate content limit exceeded after open' }
            $files.Add([ordered]@{ kind = 'file'; path = [string]$snapshot.Record.path; bytes = [Int64]$snapshot.Record.bytes; sha256 = [string]$snapshot.Record.sha256; volume_serial_hex = [string]$snapshot.Record.volume_serial_hex; file_id_hex = [string]$snapshot.Record.file_id_hex; owner_sid = [string]$snapshot.Security.OwnerSid; security_descriptor_sddl = [string]$snapshot.Security.Sddl; security_descriptor_sha256 = [string]$snapshot.Security.AclSha256 })
        }
    }
    $ancestors = [System.Collections.Generic.List[object]]::new()
    $ancestor = [IO.Path]::GetDirectoryName($root)
    while (-not [String]::IsNullOrWhiteSpace($ancestor)) {
        Assert-D32PowerShellAuthorityPreparationDeadline
        $full = [IO.Path]::GetFullPath($ancestor)
        $key = $full.TrimEnd([char[]]@('\','/'))
        if ($key.Length -eq 2 -and $key[1] -eq ':') { $key += [IO.Path]::DirectorySeparatorChar }
        $fence = $DirectoryFences[$key]
        if ($null -eq $fence) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: Defender ancestor identity is missing: $full" }
        $programData = [StringComparer]::OrdinalIgnoreCase.Equals([string]$fence.Path, 'C:\ProgramData')
        $security = [PSCustomObject]@{ Path = [string]$fence.Path; OwnerSid = [string]$fence.OwnerSid; Sddl = [string]$fence.Sddl; AclSha256 = [string]$fence.AclSha256; Security = $fence.Security }
        if (-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $security -IsDirectory:$true -IsProtectedAncestor -IsProgramDataAncestor:$programData)) {
            throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: Defender ancestor permits namespace redirection: $full"
        }
        $ancestors.Add([ordered]@{ kind = 'ancestor'; path = [string]$fence.Path; volume_serial_hex = [string]$fence.VolumeSerialHex; file_id_hex = [string]$fence.FileIdHex; owner_sid = [string]$fence.OwnerSid; security_descriptor_sddl = [string]$fence.Sddl; security_descriptor_sha256 = [string]$fence.AclSha256 })
        if ([StringComparer]::OrdinalIgnoreCase.Equals($full, [IO.Path]::GetPathRoot($full).TrimEnd([char[]]@('\','/')))) { break }
        $ancestor = [IO.Path]::GetDirectoryName($full)
    }
    if ($ancestors.Count -gt $MaximumDirectories) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: bounded Defender protected-ancestor count exceeded' }
    $sortedDirectories = [System.Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($record in $directories) { Assert-D32PowerShellAuthorityPreparationDeadline; $sortedDirectories.Add([string]$record.path,$record) }
    $sortedFiles = [System.Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($record in $files) { Assert-D32PowerShellAuthorityPreparationDeadline; $sortedFiles.Add([string]$record.path,$record) }
    $sortedAncestors = [System.Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($record in $ancestors) { $sortedAncestors.Add([string]$record.path,$record) }
    $directoryArray = @($sortedDirectories.Values); $fileArray = @($sortedFiles.Values); $ancestorArray = @($sortedAncestors.Values)
    $digest = Get-D32PowerShellAuthorityRuntimeInventoryDigest -Directories $directoryArray -Files $fileArray -Ancestors $ancestorArray
    return [ordered]@{ root_path = $root; inventory_sha256 = $digest; directories = $directoryArray; files = $fileArray; protected_ancestors = $ancestorArray; trusted_writer_sids = @('S-1-5-18','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464','S-1-5-32-544') }
}

function Get-D32PowerShellAuthorityRuntimeDistributionDiff {
    param(
        [Parameter(Mandatory = $true)][object]$Expected,
        [Parameter(Mandatory = $true)][object]$Actual,
        [Parameter(Mandatory = $true)][string]$PowerShellRoot,
        [Parameter(Mandatory = $true)][string]$WindowsRoot,
        [Parameter(Mandatory = $true)][string]$DefenderRoot
    )
    $groups = @(
        [PSCustomObject]@{ Name = 'directories'; Fields = @('kind','volume_serial_hex','file_id_hex','owner_sid','security_descriptor_sddl','security_descriptor_sha256') },
        [PSCustomObject]@{ Name = 'files'; Fields = @('kind','bytes','sha256','volume_serial_hex','file_id_hex','owner_sid','security_descriptor_sddl','security_descriptor_sha256') },
        [PSCustomObject]@{ Name = 'protected_ancestors'; Fields = @('kind','volume_serial_hex','file_id_hex','owner_sid','security_descriptor_sddl','security_descriptor_sha256') }
    )
    $added = [System.Collections.Generic.List[object]]::new()
    $removed = [System.Collections.Generic.List[object]]::new()
    $changed = [System.Collections.Generic.List[object]]::new()
    foreach ($group in $groups) {
        $expectedByPath = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
        $actualByPath = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($record in @($Expected.($group.Name))) {
            if (-not $expectedByPath.TryAdd([string]$record.path, $record)) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: pinned static component repeats a $($group.Name) path" }
        }
        foreach ($record in @($Actual.($group.Name))) {
            if (-not $actualByPath.TryAdd([string]$record.path, $record)) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: current static component repeats a $($group.Name) path" }
        }
        foreach ($record in @($Actual.($group.Name))) {
            $path = [string]$record.path
            $label = Get-D32PowerShellAuthorityResolverDiagnosticPath -Path $path -PowerShellRoot $PowerShellRoot -WindowsRoot $WindowsRoot -DefenderRoot $DefenderRoot
            if (-not $expectedByPath.ContainsKey($path)) { $added.Add([PSCustomObject]@{ group = [string]$group.Name; path = $label }); continue }
            $prior = $expectedByPath[$path]
            $fields = [System.Collections.Generic.List[string]]::new()
            if (-not [StringComparer]::Ordinal.Equals([string]$prior.path, [string]$record.path)) { $fields.Add('path_case') }
            foreach ($field in $group.Fields) {
                if ([string]$prior.$field -cne [string]$record.$field) { $fields.Add([string]$field) }
            }
            if ($fields.Count -gt 0) { $changed.Add([PSCustomObject]@{ group = [string]$group.Name; path = $label; fields = $fields.ToArray() }) }
        }
        foreach ($record in @($Expected.($group.Name))) {
            $path = [string]$record.path
            if (-not $actualByPath.ContainsKey($path)) {
                $label = Get-D32PowerShellAuthorityResolverDiagnosticPath -Path $path -PowerShellRoot $PowerShellRoot -WindowsRoot $WindowsRoot -DefenderRoot $DefenderRoot
                $removed.Add([PSCustomObject]@{ group = [string]$group.Name; path = $label })
            }
        }
    }
    return [PSCustomObject]@{ Added = $added.ToArray(); Removed = $removed.ToArray(); Changed = $changed.ToArray() }
}

function Get-D32PowerShellAuthorityCurrentOsSecurityComponents {
    param(
        [AllowEmptyString()][string]$ExpectedDefenderRoot,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$DirectoryFences,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$OpenFiles,
        [AllowNull()][object]$PinnedWindowsComponentElement
    )
    $windowsRoot = Get-D32PowerShellAuthorityWindowsRootPath
    Add-D32PowerShellAuthorityDirectoryChain -Directory $windowsRoot -Fences $DirectoryFences
    $process = [Diagnostics.Process]::GetCurrentProcess()
    $nativePaths = [System.Collections.Generic.List[string]]::new()
    try {
        foreach ($module in $process.Modules) {
            $path = [IO.Path]::GetFullPath([string]$module.FileName)
            if (-not $nativePaths.Contains($path)) { $nativePaths.Add($path) }
        }
    }
    finally { $process.Dispose() }
    $defenderPrefix = 'C:\ProgramData\Microsoft\Windows Defender\Platform'
    $defenderPaths = [System.Collections.Generic.List[string]]::new()
    $defenderRoots = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($path in $nativePaths) {
        if (Test-D32PowerShellAuthorityPathWithin -Child $path -Parent $defenderPrefix) {
            $root = [IO.Path]::GetDirectoryName($path)
            [void]$defenderRoots.Add($root)
            $defenderPaths.Add($path)
        }
        elseif (-not (Test-D32PowerShellAuthorityPathWithin -Child $path -Parent ([string]$PSHOME)) -and
            -not (Test-D32PowerShellAuthorityPathWithin -Child $path -Parent $windowsRoot)) {
            throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: unknown preloaded native image is outside PowerShell, Windows OS and the fixed Defender platform: $path"
        }
    }
    if ($defenderRoots.Count -ne 1) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: current process does not bind exactly one Defender platform root' }
    $observedDefenderRoot = [string]@($defenderRoots)[0]
    if (-not [String]::IsNullOrWhiteSpace($ExpectedDefenderRoot) -and
        -not [StringComparer]::OrdinalIgnoreCase.Equals($observedDefenderRoot, [IO.Path]::GetFullPath($ExpectedDefenderRoot))) {
        throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: current process does not bind the caller-pinned Defender platform root'
    }
    $ExpectedDefenderRoot = $observedDefenderRoot
    $requiredAnchors = @('MpOav.dll','MPCLIENT.DLL')
    $anchorPathByName = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($anchor in $requiredAnchors) {
        $matches = [System.Collections.Generic.List[string]]::new()
        foreach ($path in $defenderPaths) { if ([StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFileName($path), $anchor)) { $matches.Add($path) } }
        if ($matches.Count -ne 1) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: required Defender resolver image is absent or ambiguous: $anchor" }
        $anchorPathByName.Add($anchor, $matches[0])
    }

    $defender = Get-D32PowerShellAuthorityDefenderPlatformSnapshot -RootPath $ExpectedDefenderRoot -DirectoryFences $DirectoryFences -OpenFiles $OpenFiles
    $anchorProofs = [System.Collections.Generic.List[object]]::new()
    foreach ($anchor in $requiredAnchors) {
        $path = [string]$anchorPathByName[$anchor]
        $file = $null
        foreach ($candidate in $OpenFiles) { if ([StringComparer]::OrdinalIgnoreCase.Equals([string]$candidate.Record.path, $path)) { $file = $candidate; break } }
        if ($null -eq $file) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: Defender anchor is absent from the complete package inventory: $anchor" }
        $proof = Get-D32PowerShellAuthorityAuthenticodeSourceProof -Path $path
        $expectedVersion = [IO.Path]::GetFileName([string]$defender.root_path)
        $expectedVersion = $expectedVersion.Substring(0, $expectedVersion.LastIndexOf('-'))
        if ([string]$proof.product_version -cne $expectedVersion) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: Defender source image product version differs from its pinned platform root: $anchor" }
        $anchorProofs.Add([ordered]@{ file = [ordered]@{ path = [string]$file.Record.path; bytes = [Int64]$file.Record.bytes; sha256 = [string]$file.Record.sha256; volume_serial_hex = [string]$file.Record.volume_serial_hex; file_id_hex = [string]$file.Record.file_id_hex }; source_proof = $proof })
    }
    $process = [Diagnostics.Process]::GetCurrentProcess()
    $nativePaths = [System.Collections.Generic.List[string]]::new()
    try {
        foreach ($module in $process.Modules) {
            $path = [IO.Path]::GetFullPath([string]$module.FileName)
            if (-not $nativePaths.Contains($path)) { $nativePaths.Add($path) }
        }
    }
    finally { $process.Dispose() }
    foreach ($path in $nativePaths) {
        $underPsHome = Test-D32PowerShellAuthorityPathWithin -Child $path -Parent ([string]$PSHOME)
        $underWindows = Test-D32PowerShellAuthorityPathWithin -Child $path -Parent $windowsRoot
        $underDefender = Test-D32PowerShellAuthorityPathWithin -Child $path -Parent $defenderPrefix
        if (-not ($underPsHome -or $underWindows -or $underDefender)) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: source proof loaded an unclassified native image: $path" }
    }
    $sourceProofText = ConvertTo-D32PowerShellAuthorityJsonText -Value $anchorProofs.ToArray()
    $defenderDigestMaterial = [string]$defender.inventory_sha256 + "`n" + $sourceProofText + "`n"
    $defenderDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes($defenderDigestMaterial))).ToLowerInvariant()
    $defenderRootKey = ([IO.Path]::GetFullPath([string]$ExpectedDefenderRoot)).TrimEnd([char[]]@('\','/'))
    $defenderRootFence = $DirectoryFences[$defenderRootKey]
    $defenderNativeFiles = [System.Collections.Generic.List[object]]::new()
    foreach ($fileRecord in $defender.files) {
        foreach ($path in $defenderPaths) {
            if ([StringComparer]::OrdinalIgnoreCase.Equals([string]$fileRecord.path, $path)) { $defenderNativeFiles.Add($fileRecord); break }
        }
    }
    $defenderComponent = [ordered]@{
        component_type = 'MICROSOFT_WINDOWS_DEFENDER_PLATFORM'
        version = [string]([IO.Path]::GetFileName([string]$defender.root_path))
        root_path = [string]$defender.root_path
        root_volume_serial_hex = [string]$defenderRootFence.VolumeSerialHex
        root_file_id_hex = [string]$defenderRootFence.FileIdHex
        inventory_sha256 = $defenderDigest
        source_proof = [ordered]@{ proof_type = 'WINTRUST_CACHE_ONLY_AUTHENTICODE_V1'; status = 'VERIFIED'; anchor_images = $anchorProofs.ToArray() }
        distribution = $defender
        native_files = $defenderNativeFiles.ToArray()
    }

    $managedPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($assembly in [AppDomain]::CurrentDomain.GetAssemblies()) {
        try {
            $location = [IO.Path]::GetFullPath([string]$assembly.Location)
            if (-not [String]::IsNullOrWhiteSpace($location) -and (Test-D32PowerShellAuthorityPathWithin -Child $location -Parent $windowsRoot)) { [void]$managedPaths.Add($location) }
        }
        catch { }
    }
    $tpaText = [string][AppContext]::GetData('TRUSTED_PLATFORM_ASSEMBLIES')
    foreach ($tpaPath in $tpaText.Split([IO.Path]::PathSeparator, [StringSplitOptions]::RemoveEmptyEntries)) {
        try {
            $fullTpaPath = [IO.Path]::GetFullPath([string]$tpaPath)
            if (Test-D32PowerShellAuthorityPathWithin -Child $fullTpaPath -Parent $windowsRoot) { [void]$managedPaths.Add($fullTpaPath) }
        }
        catch { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: malformed TPA path prevents Windows OS image identity' }
    }
    foreach ($path in $nativePaths) {
        if (-not (Test-D32PowerShellAuthorityPathWithin -Child $path -Parent $windowsRoot)) { continue }
        if (-not $managedPaths.Add($path)) { continue }
    }
    $systemFilesByPath = [System.Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    if ($null -eq $PinnedWindowsComponentElement) {
        foreach ($path in $managedPaths) {
            $file = Open-D32PowerShellAuthorityFile -Path $path -DirectoryFences $DirectoryFences
            if (-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $file.Security -IsDirectory:$false)) {
                $file.Stream.Dispose()
                throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: Windows OS native/managed image namespace is not protected: $path"
            }
            $OpenFiles.Add($file)
            $systemFilesByPath.Add([string]$file.Record.path, [ordered]@{ kind = 'file'; path = [string]$file.Record.path; bytes = [Int64]$file.Record.bytes; sha256 = [string]$file.Record.sha256; volume_serial_hex = [string]$file.Record.volume_serial_hex; file_id_hex = [string]$file.Record.file_id_hex; owner_sid = [string]$file.Security.OwnerSid; security_descriptor_sddl = [string]$file.Security.Sddl; security_descriptor_sha256 = [string]$file.Security.AclSha256 })
        }
    }
    $nativeDirsText = [string][AppContext]::GetData('NATIVE_DLL_SEARCH_DIRECTORIES')
    foreach ($nativeDirectory in $nativeDirsText.Split([IO.Path]::PathSeparator, [StringSplitOptions]::RemoveEmptyEntries)) {
        $fullDirectory = [IO.Path]::GetFullPath([string]$nativeDirectory)
        if (Test-D32PowerShellAuthorityPathWithin -Child $fullDirectory -Parent $windowsRoot) {
            Add-D32PowerShellAuthorityDirectoryChain -Directory $fullDirectory -Fences $DirectoryFences
        }
    }
    $osDirectoryRecords = [System.Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    $osAncestorRecords = [System.Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($fence in $DirectoryFences.Values) {
        $path = [string]$fence.Path
        $inside = Test-D32PowerShellAuthorityPathWithin -Child $path -Parent $windowsRoot
        $ancestor = -not $inside -and (Test-D32PowerShellAuthorityPathWithin -Child $windowsRoot -Parent $path)
        if (-not ($inside -or $ancestor)) { continue }
        $security = [PSCustomObject]@{ Path = $path; OwnerSid = [string]$fence.OwnerSid; Sddl = [string]$fence.Sddl; AclSha256 = [string]$fence.AclSha256; Security = $fence.Security }
        if (-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $security -IsDirectory:$true -IsProtectedAncestor:$ancestor)) {
            throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: Windows OS resolver namespace is not protected: $path"
        }
        $record = [ordered]@{ kind = $(if ($ancestor) { 'ancestor' } else { 'directory' }); path = $path; volume_serial_hex = [string]$fence.VolumeSerialHex; file_id_hex = [string]$fence.FileIdHex; owner_sid = [string]$fence.OwnerSid; security_descriptor_sddl = [string]$fence.Sddl; security_descriptor_sha256 = [string]$fence.AclSha256 }
        if ($ancestor) { $osAncestorRecords[$path] = $record } else { $osDirectoryRecords[$path] = $record }
    }
    $windowsRootKey = $windowsRoot.TrimEnd([char[]]@('\','/'))
    $windowsRootFence = $DirectoryFences[$windowsRootKey]
    if ($null -ne $PinnedWindowsComponentElement) {
        if ($PinnedWindowsComponentElement -isnot [System.Text.Json.JsonElement]) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: caller-pinned Windows component must be a strict JSON record' }
        # The caller's finite Windows inventory is static content authority. Reopen
        # every pinned ref (including unloaded files) and keep the current loader
        # set separate for exact-origin checks in the resolver snapshot below.
        $pinnedWindowsSnapshot = Get-D32PowerShellAuthorityPinnedWindowsComponentSnapshot -Element $PinnedWindowsComponentElement `
            -DirectoryFences $DirectoryFences -OpenFiles $OpenFiles
        $windowsComponent = $pinnedWindowsSnapshot.Component
    }
    else {
        $osDistribution = [ordered]@{
            root_path = $windowsRoot
            inventory_sha256 = ''
            directories = @($osDirectoryRecords.Values)
            files = @($systemFilesByPath.Values)
            protected_ancestors = @($osAncestorRecords.Values)
            trusted_writer_sids = @('S-1-5-18','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464','S-1-5-32-544')
        }
        $osDistribution.inventory_sha256 = Get-D32PowerShellAuthorityRuntimeInventoryDigest -Directories $osDistribution.directories -Files $osDistribution.files -Ancestors $osDistribution.protected_ancestors
        if ($osDistribution.files.Count -eq 0 -or $osDistribution.directories.Count -eq 0) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: Windows OS component identity has no opened resolver image or protected namespace' }
        $osVersion = [Environment]::OSVersion.VersionString
        $osSourceProof = [ordered]@{ proof_type = 'GET_WINDOWSDIRECTORYW_OPENED_NAMESPACE_V1'; api_path = $windowsRoot; environment_system_root = [IO.Path]::GetFullPath([string]$env:SystemRoot); os_version = $osVersion }
        $osDigestMaterial = [string]$osDistribution.inventory_sha256 + "`n" + (ConvertTo-D32PowerShellAuthorityJsonText -Value $osSourceProof) + "`n"
        $osDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes($osDigestMaterial))).ToLowerInvariant()
        $windowsComponent = [ordered]@{
            component_type = 'MICROSOFT_WINDOWS_OS_INSTALLATION'
            version = [string]$osVersion
            root_path = $windowsRoot
            root_volume_serial_hex = [string]$windowsRootFence.VolumeSerialHex
            root_file_id_hex = [string]$windowsRootFence.FileIdHex
            inventory_sha256 = $osDigest
            source_proof = $osSourceProof
            distribution = $osDistribution
            native_files = @($systemFilesByPath.Values)
        }
    }
    $components = @($windowsComponent, $defenderComponent)
    $combined = [Text.StringBuilder]::new()
    foreach ($component in $components) { [void]$combined.Append([string]$component.component_type).Append('|').Append([string]$component.inventory_sha256).Append("`n") }
    $overall = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes($combined.ToString()))).ToLowerInvariant()
    return [PSCustomObject]@{ Components = $components; InventorySha256 = $overall; WindowsRoot = $windowsRoot; DefenderRoot = [string]$defender.root_path; OpenFiles = $OpenFiles; DirectoryFences = $DirectoryFences }
}

function Assert-D32PowerShellAuthorityOsSecurityComponentsCurrent {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Components,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$DirectoryFences
    )
    if ($Components.Count -ne 2 -or [string]$Components[0].component_type -cne 'MICROSOFT_WINDOWS_OS_INSTALLATION' -or
        [string]$Components[1].component_type -cne 'MICROSOFT_WINDOWS_DEFENDER_PLATFORM') {
        throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: pre-import static OS/Defender authority roles are missing or reordered'
    }
    $pinnedWindowsJson = ConvertTo-D32PowerShellAuthorityJsonText -Value $Components[0]
    $pinnedWindowsDocument = [System.Text.Json.JsonDocument]::Parse($pinnedWindowsJson)
    $verificationFiles = [System.Collections.Generic.List[object]]::new()
    try {
        $current = Get-D32PowerShellAuthorityCurrentOsSecurityComponents `
            -ExpectedDefenderRoot ([string]$Components[1].root_path) -DirectoryFences $DirectoryFences `
            -OpenFiles $verificationFiles -PinnedWindowsComponentElement $pinnedWindowsDocument.RootElement
        if ($current.Components.Count -ne 2 -or
            -not (Test-D32PowerShellAuthorityJsonMatchesObject -Element $pinnedWindowsDocument.RootElement -Value $current.Components[0])) {
            throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: full Windows OS caller pin changed during immediate pre-import reopen'
        }
        $pinnedDefenderJson = ConvertTo-D32PowerShellAuthorityJsonText -Value $Components[1]
        $pinnedDefenderDocument = [System.Text.Json.JsonDocument]::Parse($pinnedDefenderJson)
        try {
            if (-not (Test-D32PowerShellAuthorityJsonMatchesObject -Element $pinnedDefenderDocument.RootElement -Value $current.Components[1])) {
                throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: complete Defender distribution or signature source proof changed immediately before import'
            }
        }
        finally { $pinnedDefenderDocument.Dispose() }
        $expectedDigest = Get-D32PowerShellAuthorityOsSecurityInventoryDigest -Components $Components
        if ([string]$current.InventorySha256 -cne $expectedDigest) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: static OS inventory digest changed immediately before import' }
    }
    finally {
        foreach ($file in $verificationFiles) {
            if ($null -ne $file.Stream -and -not $file.Stream.SafeFileHandle.IsClosed) { $file.Stream.Dispose() }
        }
        $pinnedWindowsDocument.Dispose()
    }
}

function Get-D32PowerShellAuthorityResolverDigestSet {
    param(
        [Parameter(Mandatory = $true)][string]$ModuleSearchPath,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$OsSecurityInventorySha256,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$TrustedPlatformPaths,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$DepsPaths,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$NativeDirectories,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$NativeModulePaths,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$ActiveEnvironment,
        [Parameter(Mandatory = $true)][string]$NativePolicy,
        [Parameter(Mandatory = $true)][System.Collections.Generic.Dictionary[string,string]]$NativeFileComponents
    )
    $material = [System.Collections.Generic.List[string]]::new()
    $policyMaterial = [System.Collections.Generic.List[string]]::new()
    $material.Add($ModuleSearchPath); $policyMaterial.Add($ModuleSearchPath)
    if (-not [String]::IsNullOrWhiteSpace($OsSecurityInventorySha256)) { $material.Add($OsSecurityInventorySha256); $policyMaterial.Add($OsSecurityInventorySha256) }
    foreach ($value in @($TrustedPlatformPaths) + @($DepsPaths) + @($NativeDirectories)) { $material.Add([string]$value); $policyMaterial.Add([string]$value) }
    foreach ($path in $NativeModulePaths) {
        if (-not $NativeFileComponents.ContainsKey([string]$path)) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: resolver digest lacks an exact native component role for an observed image: $path" }
        $material.Add('native|' + [string]$path + '|' + [string]$NativeFileComponents[[string]$path])
    }
    foreach ($environmentRecord in $ActiveEnvironment) { $material.Add([string]$environmentRecord.name); $policyMaterial.Add([string]$environmentRecord.name) }
    $material.Add($NativePolicy); $policyMaterial.Add($NativePolicy)
    $encoding = [Text.UTF8Encoding]::new($false)
    $resolverDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($encoding.GetBytes([string]::Join("`n", $material.ToArray()) + "`n"))).ToLowerInvariant()
    $policyDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($encoding.GetBytes([string]::Join("`n", $policyMaterial.ToArray()) + "`n"))).ToLowerInvariant()
    $nativeDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($encoding.GetBytes([string]::Join("`n", [string[]]$NativeModulePaths) + "`n"))).ToLowerInvariant()
    return [PSCustomObject]@{ ResolverSha256 = $resolverDigest; PolicySha256 = $policyDigest; NativeModulePathsSha256 = $nativeDigest }
}

function Get-D32PowerShellAuthorityResolverSnapshot {
    param(
        [AllowNull()][string[]]$NativeModulePaths,
        [AllowNull()][string[]]$ManagedAssemblyPaths,
        [AllowNull()][string[]]$TrustedPlatformAssemblyPaths,
        [AllowNull()][string[]]$DepsFilePaths,
        [AllowNull()][string[]]$NativeDirectoryPaths,
        [AllowNull()][object[]]$OsSecurityComponents,
        [AllowNull()][string]$OsSecurityInventorySha256,
        [switch]$ConfigureNativeSearch
    )
    $powerShellRoot = [IO.Path]::GetFullPath([string]$PSHOME)
    $windowsRoot = Get-D32PowerShellAuthorityWindowsRootPath
    $blockers = [System.Collections.Generic.List[string]]::new()
    $osFileComponents = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    $osNamespaceDirectories = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if ($null -eq $OsSecurityComponents -or $OsSecurityComponents.Count -ne 2) {
        $blockers.Add('independently pinned Windows OS and Defender security-component inventories are not admitted')
    }
    else {
        try {
            $actualOsDigest = Get-D32PowerShellAuthorityOsSecurityInventoryDigest -Components $OsSecurityComponents
            if ([String]::IsNullOrWhiteSpace($OsSecurityInventorySha256) -or $actualOsDigest -cne $OsSecurityInventorySha256) { $blockers.Add('OS security component inventory digest is missing or mismatched') }
            foreach ($component in $OsSecurityComponents) {
                $type = [string]$component.component_type
                foreach ($file in @($component.native_files)) {
                    if (-not $osFileComponents.TryAdd([string]$file.path, $type)) { $blockers.Add("duplicate actual OS native origin reference: $($file.path)") }
                }
                if ($type -ceq 'MICROSOFT_WINDOWS_OS_INSTALLATION') {
                    foreach ($directory in @($component.distribution.directories)) { [void]$osNamespaceDirectories.Add([IO.Path]::GetFullPath([string]$directory.path)) }
                }
            }
        }
        catch { $blockers.Add([string]$_.Exception.Message) }
    }
    $environmentNames = @('DOTNET_STARTUP_HOOKS','DOTNET_ADDITIONAL_DEPS','DOTNET_SHARED_STORE','DOTNET_BUNDLE_EXTRACT_BASE_DIR','DOTNET_ROOT','DOTNET_ROOT_X64','DOTNET_ROOT_X86','DOTNET_MULTILEVEL_LOOKUP','CORECLR_ENABLE_PROFILING','CORECLR_PROFILER','CORECLR_PROFILER_PATH','CORECLR_PROFILER_PATH_32','CORECLR_PROFILER_PATH_64','COR_ENABLE_PROFILING','COR_PROFILER','COR_PROFILER_PATH','COR_PROFILER_PATH_32','COR_PROFILER_PATH_64')
    $activeEnvironment = [System.Collections.Generic.List[object]]::new()
    $activeEnvironmentNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $environmentNames) {
        $value = [Environment]::GetEnvironmentVariable($name, [EnvironmentVariableTarget]::Process)
        if (-not [String]::IsNullOrWhiteSpace($value) -and $value -cne '0') { $blockers.Add("startup environment injection is active: $name"); $activeEnvironment.Add([ordered]@{ name = $name; value = [string]$value }); [void]$activeEnvironmentNames.Add($name) }
    }
    foreach ($entry in [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::Process).GetEnumerator()) {
        $name = [string]$entry.Key
        if ($name -match '^(?i:DOTNET_|CORECLR_|COR_|COMPlus_)' -and $name -cnotin @('DOTNET_MULTILEVEL_LOOKUP','DOTNET_CLI_TELEMETRY_OPTOUT','DOTNET_NOLOGO')) {
            $value = [string]$entry.Value
            if (-not [String]::IsNullOrWhiteSpace($value) -and $value -cne '0' -and $activeEnvironmentNames.Add($name)) {
                $blockers.Add("unclassified runtime startup environment variable is active: $name")
                $activeEnvironment.Add([ordered]@{ name = $name; value = $value })
            }
        }
    }
    $moduleRoot = [IO.Path]::GetFullPath([IO.Path]::Combine($powerShellRoot,'Modules'))
    $moduleSearchPath = [Environment]::GetEnvironmentVariable('PSModulePath',[EnvironmentVariableTarget]::Process)
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$moduleSearchPath),$moduleRoot)) { $blockers.Add('process PSModulePath is not the exact pinned PSHOME Modules directory') }
    $tpaText = if ($null -ne $TrustedPlatformAssemblyPaths) { [string]::Join([IO.Path]::PathSeparator, [string[]]$TrustedPlatformAssemblyPaths) } else { [string][AppContext]::GetData('TRUSTED_PLATFORM_ASSEMBLIES') }
    $depsText = if ($null -ne $DepsFilePaths) { [string]::Join([IO.Path]::PathSeparator, [string[]]$DepsFilePaths) } else { [string][AppContext]::GetData('APP_CONTEXT_DEPS_FILES') }
    $nativeDirsText = if ($null -ne $NativeDirectoryPaths) { [string]::Join([IO.Path]::PathSeparator, [string[]]$NativeDirectoryPaths) } else { [string][AppContext]::GetData('NATIVE_DLL_SEARCH_DIRECTORIES') }
    if ([String]::IsNullOrWhiteSpace($tpaText) -or [String]::IsNullOrWhiteSpace($depsText) -or [String]::IsNullOrWhiteSpace($nativeDirsText)) { $blockers.Add('managed/native resolver inputs are not fully inspectable from module-free runtime metadata') }
    $trustedPlatformPaths = [string[]]$tpaText.Split([IO.Path]::PathSeparator, [StringSplitOptions]::RemoveEmptyEntries)
    $managedPaths = if ($null -ne $ManagedAssemblyPaths) { @($ManagedAssemblyPaths) } else { @($trustedPlatformPaths) }
    $depsPaths = [string[]]$depsText.Split([IO.Path]::PathSeparator, [StringSplitOptions]::RemoveEmptyEntries)
    $nativeDirs = [string[]]$nativeDirsText.Split([IO.Path]::PathSeparator, [StringSplitOptions]::RemoveEmptyEntries)
    foreach ($path in @($managedPaths) + @($depsPaths)) {
        $full = ''
        try { $full = [IO.Path]::GetFullPath([string]$path) } catch { $blockers.Add("managed assembly/deps resolver input is malformed: $path"); continue }
        $underPsHome = Test-D32PowerShellAuthorityPathWithin -Child $full -Parent $powerShellRoot
        $hasWindowsFile = $osFileComponents.ContainsKey($full) -and $osFileComponents[$full] -ceq 'MICROSOFT_WINDOWS_OS_INSTALLATION'
        if (-not [IO.Path]::IsPathRooted([string]$path) -or (-not $underPsHome -and -not $hasWindowsFile)) {
            $blockers.Add("managed assembly/deps resolver input is not an exact admitted PowerShell or Windows OS file: $path")
        }
    }
    foreach ($path in $nativeDirs) {
        $full = ''
        try { $full = [IO.Path]::GetFullPath([string]$path) } catch { $blockers.Add("native resolver directory is malformed: $path"); continue }
        $underPsHome = Test-D32PowerShellAuthorityPathWithin -Child $full -Parent $powerShellRoot
        $isPinnedOsDirectory = $osNamespaceDirectories.Contains($full)
        if (-not [IO.Path]::IsPathRooted([string]$path) -or (-not $underPsHome -and -not $isPinnedOsDirectory)) {
            $blockers.Add("native resolver directory is not an exact protected PowerShell or Windows namespace: $path")
        }
    }
    $nativePaths = if ($null -ne $NativeModulePaths) { @($NativeModulePaths) } else {
        $process = [Diagnostics.Process]::GetCurrentProcess()
        try {
            $paths = [System.Collections.Generic.List[string]]::new()
            foreach ($module in $process.Modules) { $paths.Add([IO.Path]::GetFullPath([string]$module.FileName)) }
            $paths.ToArray()
        }
        finally { $process.Dispose() }
    }
    foreach ($path in $nativePaths) {
        $full = ''
        try { $full = [IO.Path]::GetFullPath([string]$path) } catch { $blockers.Add("preloaded native image path is malformed: $path"); continue }
        if (-not (Test-D32PowerShellAuthorityPathWithin -Child $full -Parent $powerShellRoot) -and -not $osFileComponents.ContainsKey($full)) {
            $blockers.Add("preloaded native image has no exact caller-pinned OS component file reference: $path")
        }
    }
    $loadedManagedPaths = if ($null -ne $ManagedAssemblyPaths) { @($ManagedAssemblyPaths) } else {
        $paths = [System.Collections.Generic.List[string]]::new()
        foreach ($assembly in [AppDomain]::CurrentDomain.GetAssemblies()) {
            try { $location = [IO.Path]::GetFullPath([string]$assembly.Location); if (-not [String]::IsNullOrWhiteSpace($location)) { $paths.Add($location) } }
            catch { }
        }
        $paths.ToArray()
    }
    foreach ($path in $loadedManagedPaths) {
        $full = ''
        try { $full = [IO.Path]::GetFullPath([string]$path) } catch { $blockers.Add("loaded managed assembly path is malformed: $path"); continue }
        if (-not (Test-D32PowerShellAuthorityPathWithin -Child $full -Parent $powerShellRoot) -and -not $osFileComponents.ContainsKey($full)) {
            $blockers.Add("loaded managed assembly has no exact caller-pinned Windows OS component file reference: $path")
        }
    }
    $nativePolicy = 'UNCONFIGURED'
    if ($ConfigureNativeSearch -and $blockers.Count -eq 0) {
        Initialize-D32PowerShellAuthorityNativeApi
        if (-not [D32PowerShellModuleNativeV2]::SetDllDirectoryW($null) -or
            -not [D32PowerShellModuleNativeV2]::SetDefaultDllDirectories([uint32](0x00000200 -bor 0x00000800))) {
            $blockers.Add('process-local safe DLL search policy could not be configured; machine policy is not substituted')
        }
        else {
            $buffer = [Text.StringBuilder]::new(512)
            $length = [D32PowerShellModuleNativeV2]::GetDllDirectoryW([uint32]$buffer.Capacity, $buffer)
            if ($length -ne 0) { $blockers.Add('process-local DLL directory override remains active after safe-search configuration') }
            else { $nativePolicy = 'LOAD_LIBRARY_SEARCH_APPLICATION_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32; SetDllDirectoryW(NULL); verified in current process' }
        }
    }
    $sortUnique = { param([string[]]$values)
        $unique = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $list = [System.Collections.Generic.List[string]]::new()
        foreach ($value in $values) { if ($unique.Add([string]$value)) { $list.Add([string]$value) } }
        $sorted = $list.ToArray(); [Array]::Sort($sorted, [StringComparer]::OrdinalIgnoreCase); return ,$sorted
    }
    $managedSorted = & $sortUnique ([string[]]$trustedPlatformPaths)
    $loadedManagedSorted = & $sortUnique ([string[]]$loadedManagedPaths)
    $depsSorted = & $sortUnique ([string[]]$depsPaths)
    $nativeSorted = & $sortUnique ([string[]]$nativePaths)
    $nativeDirsSorted = & $sortUnique ([string[]]$nativeDirs)
    $nativeFileComponents = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($path in $nativeSorted) {
        $componentType = if ($osFileComponents.ContainsKey([string]$path)) { [string]$osFileComponents[[string]$path] } else { 'POWERSHELL_DISTRIBUTION' }
        $nativeFileComponents.Add([string]$path, $componentType)
    }
    $digests = Get-D32PowerShellAuthorityResolverDigestSet -ModuleSearchPath $moduleSearchPath -OsSecurityInventorySha256 ([string]$OsSecurityInventorySha256) `
        -TrustedPlatformPaths $managedSorted -DepsPaths $depsSorted -NativeDirectories $nativeDirsSorted -NativeModulePaths $nativeSorted `
        -ActiveEnvironment $activeEnvironment.ToArray() -NativePolicy $nativePolicy -NativeFileComponents $nativeFileComponents
    return [PSCustomObject]@{
        Blockers = [string[]]$blockers.ToArray(); TrustedPlatformPaths = [string[]]$managedSorted; LoadedManagedAssemblyPaths = [string[]]$loadedManagedSorted; DepsPaths = [string[]]$depsSorted
        NativeDirectories = [string[]]$nativeDirsSorted; NativeModulePaths = [string[]]$nativeSorted; ActiveEnvironment = $activeEnvironment.ToArray()
        NativePolicy = $nativePolicy; ModuleSearchPath = [string]$moduleSearchPath; ResolverSha256 = [string]$digests.ResolverSha256; PolicySha256 = [string]$digests.PolicySha256; NativeModulePathsSha256 = [string]$digests.NativeModulePathsSha256
        OsSecurityInventorySha256 = [string]$OsSecurityInventorySha256; OsSecurityComponents = @($OsSecurityComponents); NativeFileComponents = $nativeFileComponents
    }
}

function Get-D32PowerShellAuthorityResolverDiagnosticPath {
    param([Parameter(Mandatory = $true)][string]$Path, [string]$PowerShellRoot, [string]$WindowsRoot, [string]$DefenderRoot)
    $fullPath = $Path
    try { $fullPath = [IO.Path]::GetFullPath($Path) } catch { }
    foreach ($root in @(
        [PSCustomObject]@{ Name = 'PSHOME'; Path = $PowerShellRoot },
        [PSCustomObject]@{ Name = 'WINDOWS_OS'; Path = $WindowsRoot },
        [PSCustomObject]@{ Name = 'DEFENDER_PLATFORM'; Path = $DefenderRoot }
    )) {
        if ([String]::IsNullOrWhiteSpace([string]$root.Path)) { continue }
        $canonicalRoot = [IO.Path]::GetFullPath([string]$root.Path)
        if (-not (Test-D32PowerShellAuthorityPathWithin -Child $fullPath -Parent $canonicalRoot)) { continue }
        $rootPrefix = $canonicalRoot.TrimEnd([char[]]@('\','/'))
        if ($rootPrefix.Length -eq 2 -and $rootPrefix[1] -eq ':') { $rootPrefix += [IO.Path]::DirectorySeparatorChar }
        $relative = if ([StringComparer]::OrdinalIgnoreCase.Equals($fullPath, $canonicalRoot)) { '.' } else { $fullPath.Substring($rootPrefix.Length).TrimStart([char[]]@('\','/')) }
        return [PSCustomObject]@{ domain = [string]$root.Name; relative_path = $relative }
    }
    $pathHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes([string]$Path))).ToLowerInvariant()
    return [PSCustomObject]@{ domain = 'UNCLASSIFIED'; path_sha256 = $pathHash }
}

function Get-D32PowerShellAuthorityResolverPathDelta {
    param([AllowEmptyCollection()][string[]]$Before, [AllowEmptyCollection()][string[]]$After)
    $beforeByPath = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    $afterByPath = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    $duplicateBefore = $false
    $duplicateAfter = $false
    foreach ($path in $Before) { if (-not $beforeByPath.TryAdd([string]$path, [string]$path)) { $duplicateBefore = $true } }
    foreach ($path in $After) { if (-not $afterByPath.TryAdd([string]$path, [string]$path)) { $duplicateAfter = $true } }
    $added = [System.Collections.Generic.List[string]]::new()
    $removed = [System.Collections.Generic.List[string]]::new()
    $caseChanges = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $beforeByPath.GetEnumerator()) {
        $newPath = ''
        if (-not $afterByPath.TryGetValue([string]$entry.Key, [ref]$newPath)) { $removed.Add([string]$entry.Value); continue }
        if (-not [StringComparer]::Ordinal.Equals([string]$entry.Value, $newPath)) { $caseChanges.Add([PSCustomObject]@{ before = [string]$entry.Value; after = $newPath }) }
    }
    foreach ($entry in $afterByPath.GetEnumerator()) { if (-not $beforeByPath.ContainsKey([string]$entry.Key)) { $added.Add([string]$entry.Value) } }
    $commonBefore = [System.Collections.Generic.List[string]]::new()
    foreach ($path in $Before) { if ($afterByPath.ContainsKey([string]$path)) { $commonBefore.Add([string]$path) } }
    $commonAfter = [System.Collections.Generic.List[string]]::new()
    foreach ($path in $After) { if ($beforeByPath.ContainsKey([string]$path)) { $commonAfter.Add([string]$path) } }
    $commonOrderChanged = $commonBefore.Count -ne $commonAfter.Count
    if (-not $commonOrderChanged) {
        for ($index = 0; $index -lt $commonBefore.Count; $index++) {
            if (-not [StringComparer]::Ordinal.Equals($commonBefore[$index], $commonAfter[$index])) { $commonOrderChanged = $true; break }
        }
    }
    return [PSCustomObject]@{
        Added = [string[]]$added.ToArray(); Removed = [string[]]$removed.ToArray(); CaseChanges = $caseChanges.ToArray()
        DuplicateBefore = $duplicateBefore; DuplicateAfter = $duplicateAfter; CommonOrderChanged = $commonOrderChanged
        BeforeCount = $Before.Count; AfterCount = $After.Count
    }
}

function Add-D32PowerShellAuthorityResolverReferenceRecords {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Records,
        [Parameter(Mandatory = $true)][System.Collections.Generic.Dictionary[string,object]]$ReferenceMap,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$InvalidPaths
    )
    foreach ($record in $Records) {
        $path = [string]$record.path
        $bytes = [Int64]0
        try { $bytes = [Int64]$record.bytes } catch { }
        if ([String]::IsNullOrWhiteSpace($path) -or -not [IO.Path]::IsPathRooted($path) -or [IO.Path]::GetFullPath($path) -cne $path -or
            $bytes -le 0 -or [string]$record.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$record.volume_serial_hex -cnotmatch '^[0-9a-f]{16}$' -or [string]$record.file_id_hex -cnotmatch '^[0-9a-f]{32}$' -or
            [string]$record.owner_sid -notin @('S-1-5-18','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464','S-1-5-32-544') -or
            [string]$record.security_descriptor_sha256 -cnotmatch '^[0-9a-f]{64}$') {
            $InvalidPaths.Add($path)
            continue
        }
        if (-not $ReferenceMap.TryAdd($path, $record)) { $InvalidPaths.Add($path) }
    }
}

function Get-D32PowerShellAuthorityResolverReferenceDiagnostic {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][System.Collections.Generic.Dictionary[string,object]]$ReferenceMap,
        [string]$PowerShellRoot,
        [string]$WindowsRoot,
        [string]$DefenderRoot
    )
    $label = Get-D32PowerShellAuthorityResolverDiagnosticPath -Path $Path -PowerShellRoot $PowerShellRoot -WindowsRoot $WindowsRoot -DefenderRoot $DefenderRoot
    if (-not $ReferenceMap.ContainsKey([string]$Path)) { return [PSCustomObject]@{ location = $label; caller_pinned = $false } }
    $file = $ReferenceMap[[string]$Path]
    return [PSCustomObject]@{
        location = $label; caller_pinned = $true; bytes = [Int64]$file.bytes; sha256 = [string]$file.sha256
        volume_serial_hex = [string]$file.volume_serial_hex; file_id_hex = [string]$file.file_id_hex
        owner_sid = [string]$file.owner_sid; security_descriptor_sha256 = [string]$file.security_descriptor_sha256
    }
}

function Test-D32PowerShellAuthorityResolverSnapshotTransition {
    param(
        [Parameter(Mandatory = $true)][object]$Before,
        [Parameter(Mandatory = $true)][object]$After,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$PinnedNativeFiles,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$PinnedManagedFiles,
        [Parameter(Mandatory = $true)][string]$PowerShellRoot,
        [Parameter(Mandatory = $true)][string]$WindowsRoot,
        [Parameter(Mandatory = $true)][string]$DefenderRoot
    )
    $issues = [System.Collections.Generic.List[string]]::new()
    $policyDifferences = [System.Collections.Generic.List[string]]::new()
    $fixedPathDifferences = [System.Collections.Generic.List[object]]::new()
    $scalarDifferences = [System.Collections.Generic.List[object]]::new()
    $beforeBlockers = @($Before.Blockers)
    $afterBlockers = @($After.Blockers)
    if ($beforeBlockers.Count -gt 0) { $issues.Add('pre-import resolver snapshot has blockers') }
    if ($afterBlockers.Count -gt 0) { $issues.Add('post-import resolver snapshot has blockers') }
    $beforeDigestValid = $false
    $afterDigestValid = $false
    try {
        $beforeDigests = Get-D32PowerShellAuthorityResolverDigestSet -ModuleSearchPath ([string]$Before.ModuleSearchPath) -OsSecurityInventorySha256 ([string]$Before.OsSecurityInventorySha256) `
            -TrustedPlatformPaths ([string[]]$Before.TrustedPlatformPaths) -DepsPaths ([string[]]$Before.DepsPaths) -NativeDirectories ([string[]]$Before.NativeDirectories) `
            -NativeModulePaths ([string[]]$Before.NativeModulePaths) -ActiveEnvironment ([object[]]$Before.ActiveEnvironment) -NativePolicy ([string]$Before.NativePolicy) -NativeFileComponents $Before.NativeFileComponents
        $beforeDigestValid = $beforeDigests.ResolverSha256 -ceq [string]$Before.ResolverSha256 -and $beforeDigests.PolicySha256 -ceq [string]$Before.PolicySha256 -and $beforeDigests.NativeModulePathsSha256 -ceq [string]$Before.NativeModulePathsSha256
    }
    catch { }
    try {
        $afterDigests = Get-D32PowerShellAuthorityResolverDigestSet -ModuleSearchPath ([string]$After.ModuleSearchPath) -OsSecurityInventorySha256 ([string]$After.OsSecurityInventorySha256) `
            -TrustedPlatformPaths ([string[]]$After.TrustedPlatformPaths) -DepsPaths ([string[]]$After.DepsPaths) -NativeDirectories ([string[]]$After.NativeDirectories) `
            -NativeModulePaths ([string[]]$After.NativeModulePaths) -ActiveEnvironment ([object[]]$After.ActiveEnvironment) -NativePolicy ([string]$After.NativePolicy) -NativeFileComponents $After.NativeFileComponents
        $afterDigestValid = $afterDigests.ResolverSha256 -ceq [string]$After.ResolverSha256 -and $afterDigests.PolicySha256 -ceq [string]$After.PolicySha256 -and $afterDigests.NativeModulePathsSha256 -ceq [string]$After.NativeModulePathsSha256
    }
    catch { }
    if (-not $beforeDigestValid) { $issues.Add('pre-import resolver snapshot self-digest is invalid') }
    if (-not $afterDigestValid) { $issues.Add('post-import resolver snapshot self-digest is invalid') }
    foreach ($field in @('ModuleSearchPath','OsSecurityInventorySha256','NativePolicy','PolicySha256')) {
        if ([string]$Before.$field -cne [string]$After.$field) {
            $policyDifferences.Add($field)
            $beforeValue = [string]$Before.$field
            $afterValue = [string]$After.$field
            if ($field -ceq 'ModuleSearchPath') {
                $beforeLabel = Get-D32PowerShellAuthorityResolverDiagnosticPath -Path $beforeValue -PowerShellRoot $PowerShellRoot -WindowsRoot $WindowsRoot -DefenderRoot $DefenderRoot
                $afterLabel = Get-D32PowerShellAuthorityResolverDiagnosticPath -Path $afterValue -PowerShellRoot $PowerShellRoot -WindowsRoot $WindowsRoot -DefenderRoot $DefenderRoot
                $scalarDifferences.Add([PSCustomObject]@{ field = $field; before = $beforeLabel; after = $afterLabel })
            }
            else { $scalarDifferences.Add([PSCustomObject]@{ field = $field; before = $beforeValue; after = $afterValue }) }
        }
    }
    foreach ($field in @('TrustedPlatformPaths','DepsPaths','NativeDirectories')) {
        $beforeValues = [System.Collections.Generic.List[string]]::new()
        $afterValues = [System.Collections.Generic.List[string]]::new()
        foreach ($value in @($Before.$field)) { $beforeValues.Add([string]$value) }
        foreach ($value in @($After.$field)) { $afterValues.Add([string]$value) }
        $same = $beforeValues.Count -eq $afterValues.Count
        if ($same) {
            for ($index = 0; $index -lt $beforeValues.Count; $index++) {
                if (-not [StringComparer]::Ordinal.Equals($beforeValues[$index], $afterValues[$index])) { $same = $false; break }
            }
        }
        if (-not $same) {
            $policyDifferences.Add($field)
            $delta = Get-D32PowerShellAuthorityResolverPathDelta -Before ($beforeValues.ToArray()) -After ($afterValues.ToArray())
            $addedLabels = [System.Collections.Generic.List[object]]::new()
            foreach ($path in $delta.Added) { $addedLabels.Add((Get-D32PowerShellAuthorityResolverDiagnosticPath -Path $path -PowerShellRoot $PowerShellRoot -WindowsRoot $WindowsRoot -DefenderRoot $DefenderRoot)) }
            $removedLabels = [System.Collections.Generic.List[object]]::new()
            foreach ($path in $delta.Removed) { $removedLabels.Add((Get-D32PowerShellAuthorityResolverDiagnosticPath -Path $path -PowerShellRoot $PowerShellRoot -WindowsRoot $WindowsRoot -DefenderRoot $DefenderRoot)) }
            $caseLabels = [System.Collections.Generic.List[object]]::new()
            foreach ($change in $delta.CaseChanges) {
                $caseLabels.Add([PSCustomObject]@{
                    before = Get-D32PowerShellAuthorityResolverDiagnosticPath -Path ([string]$change.before) -PowerShellRoot $PowerShellRoot -WindowsRoot $WindowsRoot -DefenderRoot $DefenderRoot
                    after = Get-D32PowerShellAuthorityResolverDiagnosticPath -Path ([string]$change.after) -PowerShellRoot $PowerShellRoot -WindowsRoot $WindowsRoot -DefenderRoot $DefenderRoot
                })
            }
            $fixedPathDifferences.Add([PSCustomObject]@{ field = $field; before_count = $beforeValues.Count; after_count = $afterValues.Count; added = $addedLabels.ToArray(); removed = $removedLabels.ToArray(); case_changes = $caseLabels.ToArray(); common_order_changed = [bool]$delta.CommonOrderChanged })
        }
    }
    $beforeEnvironmentNames = [System.Collections.Generic.List[string]]::new()
    $afterEnvironmentNames = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in @($Before.ActiveEnvironment)) { $beforeEnvironmentNames.Add([string]$entry.name) }
    foreach ($entry in @($After.ActiveEnvironment)) { $afterEnvironmentNames.Add([string]$entry.name) }
    if ($beforeEnvironmentNames.Count -gt 0 -or $afterEnvironmentNames.Count -gt 0) { $policyDifferences.Add('ActiveEnvironment') }
    if ($beforeEnvironmentNames.Count -ne $afterEnvironmentNames.Count) { $policyDifferences.Add('ActiveEnvironmentTransition') }
    elseif ($beforeEnvironmentNames.Count -gt 0) {
        for ($index = 0; $index -lt $beforeEnvironmentNames.Count; $index++) {
            if (-not [StringComparer]::Ordinal.Equals($beforeEnvironmentNames[$index], $afterEnvironmentNames[$index])) { $policyDifferences.Add('ActiveEnvironmentTransition'); break }
        }
    }
    if ($policyDifferences.Count -gt 0) { $issues.Add('fixed resolver policy or startup environment changed') }

    $nativeDelta = Get-D32PowerShellAuthorityResolverPathDelta -Before ([string[]]@($Before.NativeModulePaths)) -After ([string[]]@($After.NativeModulePaths))
    $managedDelta = Get-D32PowerShellAuthorityResolverPathDelta -Before ([string[]]@($Before.LoadedManagedAssemblyPaths)) -After ([string[]]@($After.LoadedManagedAssemblyPaths))
    if ($nativeDelta.DuplicateBefore -or $nativeDelta.DuplicateAfter) { $issues.Add('native origin inventory contains duplicate path aliases') }
    if ($managedDelta.DuplicateBefore -or $managedDelta.DuplicateAfter) { $issues.Add('loaded managed assembly inventory contains duplicate path aliases') }
    # Native loader snapshots may include pinned OS images that were loaded by
    # earlier, module-free trust validation and are no longer resident after
    # the fixed imports.  Each before/after image is still checked against the
    # caller-pinned content inventory below; the post-import set is the one
    # persisted as the admitted origin set.  Managed assemblies remain
    # monotonic because they cannot be unloaded from this process context.
    if ($nativeDelta.CaseChanges.Count -gt 0) { $issues.Add('native image path casing changed across imports') }
    if ($nativeDelta.CommonOrderChanged) { $issues.Add('native image order changed across imports') }
    if ($managedDelta.Removed.Count -gt 0) { $issues.Add('pre-import managed assembly disappeared before admission completed') }
    if ($managedDelta.CaseChanges.Count -gt 0) { $issues.Add('managed assembly path casing changed across imports') }
    if ($managedDelta.CommonOrderChanged) { $issues.Add('managed assembly order changed across imports') }

    $nativeRoleDrift = [System.Collections.Generic.List[object]]::new()
    foreach ($path in @($Before.NativeModulePaths) + @($After.NativeModulePaths)) {
        $expectedType = if (Test-D32PowerShellAuthorityPathWithin -Child ([string]$path) -Parent $PowerShellRoot) { 'POWERSHELL_DISTRIBUTION' }
            elseif (Test-D32PowerShellAuthorityPathWithin -Child ([string]$path) -Parent $DefenderRoot) { 'MICROSOFT_WINDOWS_DEFENDER_PLATFORM' }
            elseif (Test-D32PowerShellAuthorityPathWithin -Child ([string]$path) -Parent $WindowsRoot) { 'MICROSOFT_WINDOWS_OS_INSTALLATION' }
            else { '' }
        $beforeType = if ($Before.NativeFileComponents.ContainsKey([string]$path)) { [string]$Before.NativeFileComponents[[string]$path] } else { '' }
        $afterType = if ($After.NativeFileComponents.ContainsKey([string]$path)) { [string]$After.NativeFileComponents[[string]$path] } else { '' }
        if ([String]::IsNullOrWhiteSpace($expectedType) -or ($beforeType.Length -gt 0 -and $beforeType -cne $expectedType) -or ($afterType.Length -gt 0 -and $afterType -cne $expectedType) -or
            ($beforeType.Length -gt 0 -and $afterType.Length -gt 0 -and $beforeType -cne $afterType)) {
            $nativeRoleDrift.Add([PSCustomObject]@{ path = Get-D32PowerShellAuthorityResolverDiagnosticPath -Path ([string]$path) -PowerShellRoot $PowerShellRoot -WindowsRoot $WindowsRoot -DefenderRoot $DefenderRoot; expected = $expectedType; before = $beforeType; after = $afterType })
        }
    }
    if ($nativeRoleDrift.Count -gt 0) { $issues.Add('actual native-origin component role does not match its exact pinned source domain') }
    $managedDomainDrift = [System.Collections.Generic.List[object]]::new()
    foreach ($path in @($Before.LoadedManagedAssemblyPaths) + @($After.LoadedManagedAssemblyPaths)) {
        if (-not (Test-D32PowerShellAuthorityPathWithin -Child ([string]$path) -Parent $PowerShellRoot) -and
            -not (Test-D32PowerShellAuthorityPathWithin -Child ([string]$path) -Parent $WindowsRoot)) {
            $managedDomainDrift.Add((Get-D32PowerShellAuthorityResolverDiagnosticPath -Path ([string]$path) -PowerShellRoot $PowerShellRoot -WindowsRoot $WindowsRoot -DefenderRoot $DefenderRoot))
        }
    }
    if ($managedDomainDrift.Count -gt 0) { $issues.Add('loaded managed assembly is outside the exact PowerShell/Windows content domains') }

    $nativeReferences = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    $managedReferences = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    $invalidNativeReferences = [System.Collections.Generic.List[string]]::new()
    $invalidManagedReferences = [System.Collections.Generic.List[string]]::new()
    Add-D32PowerShellAuthorityResolverReferenceRecords -Records $PinnedNativeFiles -ReferenceMap $nativeReferences -InvalidPaths $invalidNativeReferences
    Add-D32PowerShellAuthorityResolverReferenceRecords -Records $PinnedManagedFiles -ReferenceMap $managedReferences -InvalidPaths $invalidManagedReferences
    if ($invalidNativeReferences.Count -gt 0) { $issues.Add('caller-pinned native content references are malformed or duplicated') }
    if ($invalidManagedReferences.Count -gt 0) { $issues.Add('caller-pinned managed content references are malformed or duplicated') }
    $unpinnedNative = [System.Collections.Generic.List[string]]::new()
    foreach ($path in @($Before.NativeModulePaths) + @($After.NativeModulePaths)) {
        if (-not $nativeReferences.ContainsKey([string]$path)) { $unpinnedNative.Add([string]$path) }
    }
    if ($nativeDelta.Added.Count -gt 0) {
        foreach ($path in $nativeDelta.Added) { if (-not $nativeReferences.ContainsKey([string]$path)) { $issues.Add('post-import native image is outside caller-pinned content inventories'); break } }
    }
    if ($unpinnedNative.Count -gt 0) { $issues.Add('observed native image lacks an exact caller-pinned content reference') }
    $unpinnedManaged = [System.Collections.Generic.List[string]]::new()
    foreach ($path in @($Before.LoadedManagedAssemblyPaths) + @($After.LoadedManagedAssemblyPaths)) {
        if (-not $managedReferences.ContainsKey([string]$path)) { $unpinnedManaged.Add([string]$path) }
    }
    if ($managedDelta.Added.Count -gt 0) {
        foreach ($path in $managedDelta.Added) { if (-not $managedReferences.ContainsKey([string]$path)) { $issues.Add('post-import managed assembly is outside caller-pinned content inventories'); break } }
    }
    if ($unpinnedManaged.Count -gt 0) { $issues.Add('observed managed assembly lacks an exact caller-pinned content reference') }

    $nativeAddedLabels = [System.Collections.Generic.List[object]]::new()
    $nativeAddedReferences = [System.Collections.Generic.List[object]]::new()
    foreach ($path in $nativeDelta.Added) {
        $nativeAddedLabels.Add((Get-D32PowerShellAuthorityResolverDiagnosticPath -Path $path -PowerShellRoot $PowerShellRoot -WindowsRoot $WindowsRoot -DefenderRoot $DefenderRoot))
        $nativeAddedReferences.Add((Get-D32PowerShellAuthorityResolverReferenceDiagnostic -Path $path -ReferenceMap $nativeReferences -PowerShellRoot $PowerShellRoot -WindowsRoot $WindowsRoot -DefenderRoot $DefenderRoot))
    }
    $nativeRemovedLabels = [System.Collections.Generic.List[object]]::new()
    $nativeRemovedReferences = [System.Collections.Generic.List[object]]::new()
    foreach ($path in $nativeDelta.Removed) {
        $nativeRemovedLabels.Add((Get-D32PowerShellAuthorityResolverDiagnosticPath -Path $path -PowerShellRoot $PowerShellRoot -WindowsRoot $WindowsRoot -DefenderRoot $DefenderRoot))
        $nativeRemovedReferences.Add((Get-D32PowerShellAuthorityResolverReferenceDiagnostic -Path $path -ReferenceMap $nativeReferences -PowerShellRoot $PowerShellRoot -WindowsRoot $WindowsRoot -DefenderRoot $DefenderRoot))
    }
    $nativeCaseChangeLabels = [System.Collections.Generic.List[object]]::new()
    foreach ($change in $nativeDelta.CaseChanges) {
        $nativeCaseChangeLabels.Add([PSCustomObject]@{
            before = Get-D32PowerShellAuthorityResolverDiagnosticPath -Path ([string]$change.before) -PowerShellRoot $PowerShellRoot -WindowsRoot $WindowsRoot -DefenderRoot $DefenderRoot
            after = Get-D32PowerShellAuthorityResolverDiagnosticPath -Path ([string]$change.after) -PowerShellRoot $PowerShellRoot -WindowsRoot $WindowsRoot -DefenderRoot $DefenderRoot
        })
    }
    $nativeUnpinnedLabels = [System.Collections.Generic.List[object]]::new()
    foreach ($path in $unpinnedNative) { $nativeUnpinnedLabels.Add((Get-D32PowerShellAuthorityResolverDiagnosticPath -Path $path -PowerShellRoot $PowerShellRoot -WindowsRoot $WindowsRoot -DefenderRoot $DefenderRoot)) }
    $managedAddedLabels = [System.Collections.Generic.List[object]]::new()
    $managedAddedReferences = [System.Collections.Generic.List[object]]::new()
    foreach ($path in $managedDelta.Added) {
        $managedAddedLabels.Add((Get-D32PowerShellAuthorityResolverDiagnosticPath -Path $path -PowerShellRoot $PowerShellRoot -WindowsRoot $WindowsRoot -DefenderRoot $DefenderRoot))
        $managedAddedReferences.Add((Get-D32PowerShellAuthorityResolverReferenceDiagnostic -Path $path -ReferenceMap $managedReferences -PowerShellRoot $PowerShellRoot -WindowsRoot $WindowsRoot -DefenderRoot $DefenderRoot))
    }
    $managedRemovedLabels = [System.Collections.Generic.List[object]]::new()
    foreach ($path in $managedDelta.Removed) { $managedRemovedLabels.Add((Get-D32PowerShellAuthorityResolverDiagnosticPath -Path $path -PowerShellRoot $PowerShellRoot -WindowsRoot $WindowsRoot -DefenderRoot $DefenderRoot)) }
    $managedCaseChangeLabels = [System.Collections.Generic.List[object]]::new()
    foreach ($change in $managedDelta.CaseChanges) {
        $managedCaseChangeLabels.Add([PSCustomObject]@{
            before = Get-D32PowerShellAuthorityResolverDiagnosticPath -Path ([string]$change.before) -PowerShellRoot $PowerShellRoot -WindowsRoot $WindowsRoot -DefenderRoot $DefenderRoot
            after = Get-D32PowerShellAuthorityResolverDiagnosticPath -Path ([string]$change.after) -PowerShellRoot $PowerShellRoot -WindowsRoot $WindowsRoot -DefenderRoot $DefenderRoot
        })
    }
    $managedUnpinnedLabels = [System.Collections.Generic.List[object]]::new()
    foreach ($path in $unpinnedManaged) { $managedUnpinnedLabels.Add((Get-D32PowerShellAuthorityResolverDiagnosticPath -Path $path -PowerShellRoot $PowerShellRoot -WindowsRoot $WindowsRoot -DefenderRoot $DefenderRoot)) }
    $diagnostic = [ordered]@{
        record_type = 'D32_POWERSHELL_RESOLVER_TRANSITION_DIAGNOSTIC_V1'
        pre_import_resolver_sha256 = [string]$Before.ResolverSha256
        post_import_resolver_sha256 = [string]$After.ResolverSha256
        pre_import_policy_sha256 = [string]$Before.PolicySha256
        post_import_policy_sha256 = [string]$After.PolicySha256
        pre_import_native_paths_sha256 = [string]$Before.NativeModulePathsSha256
        post_import_native_paths_sha256 = [string]$After.NativeModulePathsSha256
        pre_import_resolver_digest_valid = [bool]$beforeDigestValid
        post_import_resolver_digest_valid = [bool]$afterDigestValid
        pre_import_blocker_count = $beforeBlockers.Count
        post_import_blocker_count = $afterBlockers.Count
        fixed_policy_differences = $policyDifferences.ToArray()
        fixed_policy_scalar_differences = $scalarDifferences.ToArray()
        fixed_policy_path_differences = $fixedPathDifferences.ToArray()
        active_environment = [ordered]@{ before_names = $beforeEnvironmentNames.ToArray(); after_names = $afterEnvironmentNames.ToArray(); values_omitted = $true }
        native_component_role_differences = $nativeRoleDrift.ToArray()
        managed_domain_differences = $managedDomainDrift.ToArray()
        native_images = [ordered]@{ pre_count = $nativeDelta.BeforeCount; post_count = $nativeDelta.AfterCount; added = $nativeAddedLabels.ToArray(); added_content_refs = $nativeAddedReferences.ToArray(); removed = $nativeRemovedLabels.ToArray(); removed_content_refs = $nativeRemovedReferences.ToArray(); case_changes = $nativeCaseChangeLabels.ToArray(); common_order_changed = [bool]$nativeDelta.CommonOrderChanged; unpinned = $nativeUnpinnedLabels.ToArray() }
        managed_assemblies = [ordered]@{ pre_count = $managedDelta.BeforeCount; post_count = $managedDelta.AfterCount; added = $managedAddedLabels.ToArray(); added_content_refs = $managedAddedReferences.ToArray(); removed = $managedRemovedLabels.ToArray(); case_changes = $managedCaseChangeLabels.ToArray(); common_order_changed = [bool]$managedDelta.CommonOrderChanged; unpinned = $managedUnpinnedLabels.ToArray() }
        issues = $issues.ToArray()
    }
    return [PSCustomObject]@{ Passed = ($issues.Count -eq 0); Diagnostic = $diagnostic }
}

function Assert-D32PowerShellAuthorityRuntimeDistributionRecord {
    param([Parameter(Mandatory = $true)][System.Text.Json.JsonElement]$Element, [Parameter(Mandatory = $true)][object]$Actual)
    Assert-D32PowerShellAuthorityExactJsonRecord -Element $Element -Fields @('root_path','inventory_sha256','directories','files','protected_ancestors','trusted_writer_sids') -Name 'complete PowerShell distribution authority'
    if ((Get-D32PowerShellAuthorityJsonString $Element 'root_path') -cne [string]$Actual.root_path -or
        (Get-D32PowerShellAuthorityJsonString $Element 'inventory_sha256') -cne [string]$Actual.inventory_sha256) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: pinned complete PowerShell distribution root or digest mismatch' }
    $specs = @(
        [PSCustomObject]@{ Name = 'directories'; Items = @($Actual.directories); Fields = @('kind','path','volume_serial_hex','file_id_hex','owner_sid','security_descriptor_sddl','security_descriptor_sha256') },
        [PSCustomObject]@{ Name = 'files'; Items = @($Actual.files); Fields = @('kind','path','bytes','sha256','volume_serial_hex','file_id_hex','owner_sid','security_descriptor_sddl','security_descriptor_sha256') },
        [PSCustomObject]@{ Name = 'protected_ancestors'; Items = @($Actual.protected_ancestors); Fields = @('kind','path','volume_serial_hex','file_id_hex','owner_sid','security_descriptor_sddl','security_descriptor_sha256') }
    )
    foreach ($spec in $specs) {
        $array = $Element.GetProperty([string]$spec.Name)
        if ($array.ValueKind -ne [System.Text.Json.JsonValueKind]::Array -or $array.GetArrayLength() -ne $spec.Items.Count) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: full runtime $($spec.Name) inventory is incomplete" }
        $index = 0
        foreach ($itemElement in $array.EnumerateArray()) {
            Assert-D32PowerShellAuthorityExactJsonRecord -Element $itemElement -Fields $spec.Fields -Name "runtime $($spec.Name) entry"
            $expected = $spec.Items[$index]
            foreach ($field in $spec.Fields) {
                $property = $itemElement.GetProperty([string]$field)
                if ($field -ceq 'bytes') {
                    if ($property.ValueKind -ne [System.Text.Json.JsonValueKind]::Number -or $property.GetInt64() -ne [Int64]$expected.bytes) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: runtime distribution bytes differ: $($expected.path)" }
                }
                elseif ($property.ValueKind -ne [System.Text.Json.JsonValueKind]::String -or $property.GetString() -cne [string]$expected.$field) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: runtime distribution content/ACL identity differs: $($expected.path)" }
            }
            $index++
        }
    }
    $trusted = $Element.GetProperty('trusted_writer_sids')
    $expectedTrust = @('S-1-5-18','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464','S-1-5-32-544')
    if ($trusted.ValueKind -ne [System.Text.Json.JsonValueKind]::Array -or $trusted.GetArrayLength() -ne $expectedTrust.Count) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: protected namespace writer policy is missing or expanded' }
    for ($index=0; $index -lt $expectedTrust.Count; $index++) { if ($trusted[$index].ValueKind -ne [System.Text.Json.JsonValueKind]::String -or $trusted[$index].GetString() -cne $expectedTrust[$index]) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: protected namespace trusted writer policy differs' } }
}

function Assert-D32PowerShellAuthorityResolverPolicyRecord {
    param(
        [Parameter(Mandatory = $true)][System.Text.Json.JsonElement]$Element,
        [Parameter(Mandatory = $true)][string]$PowerShellRoot,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$DirectoryFences,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$OpenFiles
    )
    Assert-D32PowerShellAuthorityExactJsonRecord -Element $Element -Fields @('policy_id','managed_distribution_root','managed_os_root','native_application_root','native_system_root','native_search_flags','forbidden_sources','os_security_components') -Name 'PowerShell resolver policy'
    $windowsRoot = Get-D32PowerShellAuthorityWindowsRootPath
    if ((Get-D32PowerShellAuthorityJsonString $Element 'policy_id') -cne 'D32_POWERSHELL_RESOLVER_DOMAIN_V2' -or
        (Get-D32PowerShellAuthorityJsonString $Element 'managed_distribution_root') -cne [IO.Path]::GetFullPath($PowerShellRoot) -or
        (Get-D32PowerShellAuthorityJsonString $Element 'managed_os_root') -cne $windowsRoot -or
        (Get-D32PowerShellAuthorityJsonString $Element 'native_application_root') -cne [IO.Path]::GetFullPath($PowerShellRoot) -or
        (Get-D32PowerShellAuthorityJsonString $Element 'native_system_root') -cne $windowsRoot) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: external authority resolver roots do not bind this current runtime and OS' }
    $expected = @(
        [PSCustomObject]@{ Field = 'native_search_flags'; Values = @('LOAD_LIBRARY_SEARCH_APPLICATION_DIR','LOAD_LIBRARY_SEARCH_SYSTEM32') },
        [PSCustomObject]@{ Field = 'forbidden_sources'; Values = @('CWD','PATH','USER_PSMODULEPATH','STARTUP_HOOKS','EXTERNAL_ASSEMBLIES','UNPINNED_DLL_DIRECTORIES') }
    )
    foreach ($item in $expected) {
        $array = $Element.GetProperty([string]$item.Field)
        if ($array.ValueKind -ne [System.Text.Json.JsonValueKind]::Array -or $array.GetArrayLength() -ne $item.Values.Count) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: resolver policy list differs: $($item.Field)" }
        for ($index=0; $index -lt $item.Values.Count; $index++) { if ($array[$index].ValueKind -ne [System.Text.Json.JsonValueKind]::String -or $array[$index].GetString() -cne $item.Values[$index]) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: resolver policy list differs: $($item.Field)" } }
    }
    $componentElements = $Element.GetProperty('os_security_components')
    if ($componentElements.ValueKind -ne [System.Text.Json.JsonValueKind]::Array -or $componentElements.GetArrayLength() -ne 2 -or
        (Get-D32PowerShellAuthorityJsonString $componentElements[0] 'component_type') -cne 'MICROSOFT_WINDOWS_OS_INSTALLATION' -or
        (Get-D32PowerShellAuthorityJsonString $componentElements[1] 'component_type') -cne 'MICROSOFT_WINDOWS_DEFENDER_PLATFORM') {
        throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: resolver policy lacks the two fixed Windows OS security-component roles'
    }
    $defenderRoot = Get-D32PowerShellAuthorityJsonString $componentElements[1] 'root_path'
    $components = Get-D32PowerShellAuthorityCurrentOsSecurityComponents -ExpectedDefenderRoot $defenderRoot -DirectoryFences $DirectoryFences `
        -OpenFiles $OpenFiles -PinnedWindowsComponentElement $componentElements[0]
    for ($index = 0; $index -lt 2; $index++) {
        if (-not (Test-D32PowerShellAuthorityJsonMatchesObject -Element $componentElements[$index] -Value $components.Components[$index])) {
            throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: independently pinned OS security component content, source or opened identity differs: $index"
        }
    }
    return $components
}

function Assert-D32PowerShellAuthorityRuntimeSnapshotCurrent {
    param([Parameter(Mandatory = $true)][object]$Snapshot, [Parameter(Mandatory = $true)][System.Collections.IDictionary]$DirectoryFences, [Parameter(Mandatory = $true)][System.Collections.Generic.List[object]]$OpenFiles)
    $expectedChildren = [System.Collections.Generic.Dictionary[string,System.Collections.Generic.HashSet[string]]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($directory in @($Snapshot.directories)) { $expectedChildren[[string]$directory.path] = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase) }
    foreach ($item in @($Snapshot.directories) + @($Snapshot.files)) {
        if ([StringComparer]::OrdinalIgnoreCase.Equals([string]$item.path,[string]$Snapshot.root_path)) { continue }
        $parent = [IO.Path]::GetDirectoryName([string]$item.path)
        if (-not $expectedChildren.ContainsKey($parent) -or -not $expectedChildren[$parent].Add([string]$item.path)) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: full runtime inventory parent or path alias is invalid: $($item.path)" }
    }
    foreach ($directory in @($Snapshot.directories) + @($Snapshot.protected_ancestors)) {
        $path = [string]$directory.path
        $key = $path.TrimEnd([char[]]@('\','/'))
        if ($key.Length -eq 2 -and $key[1] -eq ':') { $key += [IO.Path]::DirectorySeparatorChar }
        $fence = $DirectoryFences[$key]
        if ($null -eq $fence -or $fence.Handle.IsClosed -or $fence.Handle.IsInvalid) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: runtime directory handle is missing: $path" }
        $identity = Get-D32PowerShellAuthorityHandleIdentity -Handle $fence.Handle
        if (($identity.Attributes -band [int][IO.FileAttributes]::Directory) -eq 0 -or ($identity.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $identity.VolumeSerialHex -cne [string]$directory.volume_serial_hex -or $identity.FileIdHex -cne [string]$directory.file_id_hex -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals((Get-D32PowerShellAuthorityFinalHandlePath -Handle $fence.Handle), $path)) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: runtime directory object/path changed before import: $path" }
        $security = Get-D32PowerShellAuthorityObjectSecurity -Path $path -IsDirectory:$true -Handle $fence.Handle
        $isProtectedAncestor = [string]$directory.kind -ceq 'ancestor'
        if (-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $security -IsDirectory:$true -IsProtectedAncestor:$isProtectedAncestor) -or
            $security.OwnerSid -cne [string]$directory.owner_sid -or $security.AclSha256 -cne [string]$directory.security_descriptor_sha256) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: runtime directory namespace protection changed before import: $path" }
        if ($expectedChildren.ContainsKey($path)) {
            $actualChildren = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($path)) {
                $entryPath = [IO.Path]::GetFullPath([string]$entry)
                if (-not $actualChildren.Add($entryPath) -or -not $expectedChildren[$path].Contains($entryPath)) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: unexpected or aliased runtime resolver entry appeared before import: $entryPath" }
                if (([IO.File]::GetAttributes($entryPath) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: runtime resolver entry became a reparse point: $entryPath" }
            }
            if ($actualChildren.Count -ne $expectedChildren[$path].Count) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: a runtime distribution entry disappeared before import: $path" }
        }
    }
    foreach ($expected in @($Snapshot.files)) {
        $fileSnapshot = $null
        foreach ($candidate in $OpenFiles) { if ([StringComparer]::OrdinalIgnoreCase.Equals([string]$candidate.Record.path,[string]$expected.path)) { $fileSnapshot = $candidate; break } }
        if ($null -eq $fileSnapshot -or $null -eq $fileSnapshot.Stream -or $fileSnapshot.Stream.SafeFileHandle.IsClosed) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: runtime distribution content handle is missing: $($expected.path)" }
        $identity = Get-D32PowerShellAuthorityHandleIdentity -Handle $fileSnapshot.Stream.SafeFileHandle
        if ($identity.VolumeSerialHex -cne [string]$expected.volume_serial_hex -or $identity.FileIdHex -cne [string]$expected.file_id_hex -or $identity.Bytes -ne [Int64]$expected.bytes -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals((Get-D32PowerShellAuthorityFinalHandlePath -Handle $fileSnapshot.Stream.SafeFileHandle),[string]$expected.path)) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: runtime distribution file object/path changed before import: $($expected.path)" }
        $fileSnapshot.Stream.Position = 0
        $sha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($fileSnapshot.Stream)).ToLowerInvariant()
        if ($sha -cne [string]$expected.sha256 -or $fileSnapshot.Stream.Length -ne [Int64]$expected.bytes) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: runtime distribution file content changed before import: $($expected.path)" }
        $security = Get-D32PowerShellAuthorityObjectSecurity -Path ([string]$expected.path) -IsDirectory:$false -Handle $fileSnapshot.Stream.SafeFileHandle -Stream $fileSnapshot.Stream
        if (-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $security -IsDirectory:$false) -or
            $security.OwnerSid -cne [string]$expected.owner_sid -or $security.AclSha256 -cne [string]$expected.security_descriptor_sha256) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: runtime file namespace protection changed before import: $($expected.path)" }
    }
}

function Assert-D32PowerShellAuthorityRuntimeEntriesCurrent {
    param([Parameter(Mandatory = $true)][object]$Snapshot)
    $expectedChildren = [System.Collections.Generic.Dictionary[string,System.Collections.Generic.HashSet[string]]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($directory in @($Snapshot.directories)) { $expectedChildren[[string]$directory.path] = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase) }
    foreach ($item in @($Snapshot.directories) + @($Snapshot.files)) {
        if ([StringComparer]::OrdinalIgnoreCase.Equals([string]$item.path,[string]$Snapshot.root_path)) { continue }
        $parent = [IO.Path]::GetDirectoryName([string]$item.path)
        if (-not $expectedChildren.ContainsKey($parent) -or -not $expectedChildren[$parent].Add([string]$item.path)) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: runtime inventory parent changed or paths alias: $($item.path)" }
    }
    foreach ($directoryPath in $expectedChildren.Keys) {
        $actualChildren = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries([string]$directoryPath)) {
            $path = [IO.Path]::GetFullPath([string]$entry)
            if (-not $actualChildren.Add($path) -or -not $expectedChildren[$directoryPath].Contains($path) -or
                ([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: unpinned or redirected resolver candidate exists: $path" }
        }
        if ($actualChildren.Count -ne $expectedChildren[$directoryPath].Count) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: runtime resolver candidate inventory changed: $directoryPath" }
    }
}

function Assert-D32PowerShellAuthorityExactJsonRecord {
    param([System.Text.Json.JsonElement]$Element, [string[]]$Fields, [string]$Name)
    if (-not (Test-D32PowerShellAuthorityJsonFields -Element $Element -Expected $Fields)) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: $Name has unknown, missing, or wrong property set" }
}

function Test-D32PowerShellAuthorityJsonMatchesObject {
    param([Parameter(Mandatory = $true)][System.Text.Json.JsonElement]$Element, [AllowNull()][object]$Value)
    if ($null -eq $Value) { return $Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Null }
    if ($Value -is [string]) { return $Element.ValueKind -eq [System.Text.Json.JsonValueKind]::String -and $Element.GetString() -ceq $Value }
    if ($Value -is [bool]) { return $Element.ValueKind -eq [System.Text.Json.JsonValueKind]::True -and $Value -or $Element.ValueKind -eq [System.Text.Json.JsonValueKind]::False -and -not $Value }
    if ($Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or $Value -is [uint16] -or $Value -is [int32] -or $Value -is [uint32] -or $Value -is [int64] -or $Value -is [uint64]) {
        return $Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Number -and $Element.GetInt64() -eq [Int64]$Value
    }
    if ($Value -is [System.Collections.IDictionary] -or $Value -is [System.Management.Automation.PSCustomObject]) {
        $names = [System.Collections.Generic.List[string]]::new()
        if ($Value -is [System.Collections.IDictionary]) { foreach ($key in $Value.Keys) { $names.Add([string]$key) } }
        else { foreach ($property in $Value.PSObject.Properties) { $names.Add([string]$property.Name) } }
        if ($Element.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { return $false }
        $propertyCount = 0
        foreach ($property in $Element.EnumerateObject()) { $propertyCount++ }
        if ($propertyCount -ne $names.Count) { return $false }
        foreach ($name in $names) {
            $property = [System.Text.Json.JsonElement]::new()
            if (-not $Element.TryGetProperty($name, [ref]$property)) { return $false }
            # Assign outside an if-expression: PowerShell enumerates output from
            # the expression pipeline, which collapses a one-element array and
            # makes strict JSON shape checks misread nested singleton arrays.
            if ($Value -is [System.Collections.IDictionary]) { $child = $Value[$name] }
            else { $child = $Value.PSObject.Properties[$name].Value }
            if (-not (Test-D32PowerShellAuthorityJsonMatchesObject -Element $property -Value $child)) { return $false }
        }
        return $true
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        if ($Value -is [string] -or $Element.ValueKind -ne [System.Text.Json.JsonValueKind]::Array) { return $false }
        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Value) { $items.Add($item) }
        if ($Element.GetArrayLength() -ne $items.Count) { return $false }
        for ($index = 0; $index -lt $items.Count; $index++) {
            if (-not (Test-D32PowerShellAuthorityJsonMatchesObject -Element $Element[$index] -Value $items[$index])) { return $false }
        }
        return $true
    }
    return $false
}

function Get-D32PowerShellAuthorityJsonString {
    param([System.Text.Json.JsonElement]$Element, [string]$Name)
    $property = $Element.GetProperty($Name)
    if ($property.ValueKind -ne [System.Text.Json.JsonValueKind]::String) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: $Name must be a JSON string" }
    return $property.GetString()
}

function Assert-D32PowerShellAuthorityFileRecord {
    param([System.Text.Json.JsonElement]$Element, [object]$Actual, [string]$Name)
    Assert-D32PowerShellAuthorityExactJsonRecord -Element $Element -Fields @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex') -Name $Name
    if ($Element.GetProperty('path').GetString() -cne [string]$Actual.Record.path -or
        $Element.GetProperty('bytes').ValueKind -ne [System.Text.Json.JsonValueKind]::Number -or $Element.GetProperty('bytes').GetInt64() -ne [Int64]$Actual.Record.bytes -or
        $Element.GetProperty('sha256').GetString() -cne [string]$Actual.Record.sha256 -or
        $Element.GetProperty('volume_serial_hex').GetString() -cne [string]$Actual.Record.volume_serial_hex -or
        $Element.GetProperty('file_id_hex').GetString() -cne [string]$Actual.Record.file_id_hex) {
        throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: $Name differs from the independently pinned opened content identity"
    }
}

function Assert-D32PowerShellAuthorityDirectoryRecord {
    param([System.Text.Json.JsonElement]$Element, [object]$Actual, [string]$Name)
    Assert-D32PowerShellAuthorityExactJsonRecord -Element $Element -Fields @('path', 'volume_serial_hex', 'file_id_hex') -Name $Name
    if ($Element.GetProperty('path').GetString() -cne [string]$Actual.Path -or
        $Element.GetProperty('volume_serial_hex').GetString() -cne [string]$Actual.VolumeSerialHex -or
        $Element.GetProperty('file_id_hex').GetString() -cne [string]$Actual.FileIdHex) {
        throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: $Name differs from the opened directory identity"
    }
}

function Test-D32PowerShellModuleAdmissionClosureFileRecord {
    param(
        [AllowNull()][object]$FileRecord,
        [Parameter(Mandatory = $true)][string]$Role,
        [Parameter(Mandatory = $true)][string]$ModuleDirectory,
        [Parameter(Mandatory = $true)][string[]]$AllowedRootFilePaths,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.HashSet[string]]$SeenPaths,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.HashSet[string]]$SeenFileIds
    )
    $script:D32PowerShellModuleAdmissionValidationContext = "record.module-closure.$Role.file.property-set"
    if ($null -eq $FileRecord -or $FileRecord -is [string] -or $FileRecord -is [Array] -or $FileRecord -is [ValueType]) { return $false }
    $fileNames = [System.Collections.Generic.List[string]]::new()
    if ($FileRecord -is [System.Collections.IDictionary]) { foreach ($key in $FileRecord.Keys) { $fileNames.Add([string]$key) } }
    else { foreach ($property in $FileRecord.PSObject.Properties) { $fileNames.Add([string]$property.Name) } }
    $referenceFields = @('path','sha256','bytes','volume_serial_hex','file_id_hex')
    if ($fileNames.Count -ne $referenceFields.Count) { return $false }
    foreach ($field in $referenceFields) { if (-not $fileNames.Contains($field)) { return $false } }

    $get = {
        param($record, $name)
        $value = Get-D32PowerShellModuleAdmissionField -Record $record -Name $name
        if ($value -is [Array]) { return ,$value }
        return $value
    }
    $filePath = & $get $FileRecord 'path'
    $fileSha = & $get $FileRecord 'sha256'
    $fileBytes = & $get $FileRecord 'bytes'
    $volume = & $get $FileRecord 'volume_serial_hex'
    $fileId = & $get $FileRecord 'file_id_hex'

    $script:D32PowerShellModuleAdmissionValidationContext = "record.module-closure.$Role.file.identity-types"
    if ($filePath -isnot [string] -or -not [IO.Path]::IsPathRooted($filePath) -or
        $fileSha -isnot [string] -or $fileSha -cnotmatch '^[0-9a-f]{64}$' -or
        -not ($fileBytes -is [int32] -or $fileBytes -is [int64] -or $fileBytes -is [uint32] -or $fileBytes -is [uint64]) -or [Int64]$fileBytes -le 0 -or
        $volume -isnot [string] -or $volume -cnotmatch '^[0-9a-f]{16}$' -or
        $fileId -isnot [string] -or $fileId -cnotmatch '^[0-9a-f]{32}$') { return $false }
    try {
        if ([IO.Path]::GetFullPath($filePath) -cne $filePath) { return $false }
    }
    catch { return $false }

    $script:D32PowerShellModuleAdmissionValidationContext = "record.module-closure.$Role.file.role-boundary"
    if (-not (Test-D32PowerShellAuthorityPathWithin -Child $filePath -Parent $ModuleDirectory) -and $filePath -cnotin $AllowedRootFilePaths) { return $false }

    $script:D32PowerShellModuleAdmissionValidationContext = "record.module-closure.$Role.file.unique-path"
    if ($SeenPaths.Contains($filePath)) { return $false }
    $script:D32PowerShellModuleAdmissionValidationContext = "record.module-closure.$Role.file.unique-file-id"
    $fileIdentity = [string]$volume + ':' + [string]$fileId
    if ($SeenFileIds.Contains($fileIdentity)) { return $false }
    [void]$SeenPaths.Add($filePath)
    [void]$SeenFileIds.Add($fileIdentity)
    return $true
}

function Test-D32PowerShellModuleAdmissionAssemblyOriginRecord {
    param(
        [AllowNull()][object]$AssemblyRecord,
        [Parameter(Mandatory = $true)][System.Collections.Generic.Dictionary[string,object]]$FileRecordsByPath,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.HashSet[string]]$SeenAssemblyPaths
    )
    $script:D32PowerShellModuleAdmissionValidationContext = 'record.actual-assembly-origin.property-set'
    if ($null -eq $AssemblyRecord -or $AssemblyRecord -is [string] -or $AssemblyRecord -is [Array] -or $AssemblyRecord -is [ValueType]) { return $false }
    $assemblyFields = [System.Collections.Generic.List[string]]::new()
    if ($AssemblyRecord -is [System.Collections.IDictionary]) { foreach ($key in $AssemblyRecord.Keys) { $assemblyFields.Add([string]$key) } }
    else { foreach ($property in $AssemblyRecord.PSObject.Properties) { $assemblyFields.Add([string]$property.Name) } }
    $referenceFields = @('path','sha256','bytes','volume_serial_hex','file_id_hex')
    if ($assemblyFields.Count -ne $referenceFields.Count) { return $false }
    foreach ($field in $referenceFields) { if (-not $assemblyFields.Contains($field)) { return $false } }

    $get = {
        param($record, $name)
        $value = Get-D32PowerShellModuleAdmissionField -Record $record -Name $name
        if ($value -is [Array]) { return ,$value }
        return $value
    }
    $path = & $get $AssemblyRecord 'path'
    $sha = & $get $AssemblyRecord 'sha256'
    $bytes = & $get $AssemblyRecord 'bytes'
    $volume = & $get $AssemblyRecord 'volume_serial_hex'
    $fileId = & $get $AssemblyRecord 'file_id_hex'
    $script:D32PowerShellModuleAdmissionValidationContext = 'record.actual-assembly-origin.identity-types'
    if ($path -isnot [string] -or -not [IO.Path]::IsPathRooted($path) -or
        $sha -isnot [string] -or $sha -cnotmatch '^[0-9a-f]{64}$' -or
        -not ($bytes -is [int32] -or $bytes -is [int64] -or $bytes -is [uint32] -or $bytes -is [uint64]) -or [Int64]$bytes -le 0 -or
        $volume -isnot [string] -or $volume -cnotmatch '^[0-9a-f]{16}$' -or
        $fileId -isnot [string] -or $fileId -cnotmatch '^[0-9a-f]{32}$') { return $false }
    try {
        if ([IO.Path]::GetFullPath($path) -cne $path) { return $false }
    }
    catch { return $false }

    $script:D32PowerShellModuleAdmissionValidationContext = 'record.actual-assembly-origin.pinned-closure-path'
    if (-not $FileRecordsByPath.ContainsKey($path)) { return $false }
    $file = $FileRecordsByPath[$path]
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($path, [string](& $get $file 'path'))) { return $false }

    $script:D32PowerShellModuleAdmissionValidationContext = 'record.actual-assembly-origin.unique-path'
    if ($SeenAssemblyPaths.Contains($path)) { return $false }
    $script:D32PowerShellModuleAdmissionValidationContext = 'record.actual-assembly-origin.sha256-reference'
    if ($sha -cne (& $get $file 'sha256')) { return $false }
    $script:D32PowerShellModuleAdmissionValidationContext = 'record.actual-assembly-origin.bytes-reference'
    if ([Int64]$bytes -ne [Int64](& $get $file 'bytes')) { return $false }
    $script:D32PowerShellModuleAdmissionValidationContext = 'record.actual-assembly-origin.volume-reference'
    if ($volume -cne (& $get $file 'volume_serial_hex')) { return $false }
    $script:D32PowerShellModuleAdmissionValidationContext = 'record.actual-assembly-origin.file-id-reference'
    if ($fileId -cne (& $get $file 'file_id_hex')) { return $false }
    [void]$SeenAssemblyPaths.Add($path)
    return $true
}

function Test-D32PowerShellModuleAdmissionRecord {
    param([AllowNull()][object]$Document, [AllowNull()][string]$CandidateSha, [AllowNull()][string]$Repository, [AllowNull()][object]$ExpectedContext)
    $script:D32PowerShellModuleAdmissionValidationContext = 'record.shape'
    $fields = @('record_type','schema_version','status','candidate_sha','source_repo','authority_reference','profile_reference','git_image','powershell_host','runner_process','startup','entry_script_path','entry_script','module_import_order','module_closure','resolver_admission','import_verification','import_attempts')
    if ($null -eq $Document -or $Document -is [string] -or $Document -is [Array] -or $Document -is [ValueType]) { return $false }
    $actual = [System.Collections.Generic.List[string]]::new()
    if ($Document -is [System.Collections.IDictionary]) { foreach ($key in $Document.Keys) { $actual.Add([string]$key) } }
    else { foreach ($property in $Document.PSObject.Properties) { $actual.Add([string]$property.Name) } }
    if ($actual.Count -ne $fields.Count) { return $false }
    foreach ($field in $fields) { if (-not $actual.Contains($field)) { return $false } }
    $get = {
        param($object, $name)
        $value = Get-D32PowerShellModuleAdmissionField -Record $object -Name $name
        if ($value -is [Array]) { return ,$value }
        return $value
    }
    $recordType = Get-D32PowerShellModuleAdmissionField -Record $Document -Name 'record_type'; $version = Get-D32PowerShellModuleAdmissionField -Record $Document -Name 'schema_version'; $status = Get-D32PowerShellModuleAdmissionField -Record $Document -Name 'status'
    $candidate = Get-D32PowerShellModuleAdmissionField -Record $Document -Name 'candidate_sha'; $repository = Get-D32PowerShellModuleAdmissionField -Record $Document -Name 'source_repo'; $attempts = Get-D32PowerShellModuleAdmissionField -Record $Document -Name 'import_attempts'
    $order = Get-D32PowerShellModuleAdmissionField -Record $Document -Name 'module_import_order'
    $script:D32PowerShellModuleAdmissionValidationContext = 'record.repository-canonical-path'
    $recordRepositoryIdentity = if ($repository -is [string]) { ConvertTo-D32PowerShellModuleLocalPathIdentity -Path $repository } else { $null }
    if ($null -eq $recordRepositoryIdentity) { return $false }
    $script:D32PowerShellModuleAdmissionValidationContext = 'record.repository-caller-path'
    $callerRepositoryIdentity = if ($Repository -is [string]) { ConvertTo-D32PowerShellModuleLocalPathIdentity -Path $Repository } else { $null }
    if ($null -eq $callerRepositoryIdentity) { return $false }
    $script:D32PowerShellModuleAdmissionValidationContext = 'record.repository-representation'
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($recordRepositoryIdentity, $callerRepositoryIdentity)) { return $false }
    $script:D32PowerShellModuleAdmissionValidationContext = 'record.scalar-fields-and-import-order'
    if ($recordType -isnot [string] -or $recordType -cne 'D32_POWERSHELL_MODULE_ADMISSION_V2' -or
        -not ($version -is [byte] -or $version -is [int16] -or $version -is [uint16] -or $version -is [int32] -or $version -is [uint32] -or $version -is [int64] -or $version -is [uint64]) -or [Int64]$version -ne 2 -or
        $status -isnot [string] -or $status -cne 'ADMITTED' -or $candidate -isnot [string] -or $candidate -cnotmatch '^[0-9a-f]{40}$' -or
        (-not [String]::IsNullOrWhiteSpace($CandidateSha) -and $candidate -cne $CandidateSha) -or
        $repository -isnot [string] -or
        -not ($attempts -is [byte] -or $attempts -is [int16] -or $attempts -is [uint16] -or $attempts -is [int32] -or $attempts -is [uint32] -or $attempts -is [int64] -or $attempts -is [uint64]) -or [Int64]$attempts -ne 3 -or
        $order -isnot [Array] -or $order.Count -ne 3 -or ($order -join "`n") -cne "Microsoft.PowerShell.Management`nMicrosoft.PowerShell.Utility`nCimCmdlets") { return $false }
    $script:D32PowerShellModuleAdmissionValidationContext = 'record.repository-and-entry-path'
    $entryPathForRepository = & $get $Document 'entry_script_path'
    $entryPathIdentity = if ($entryPathForRepository -is [string]) { ConvertTo-D32PowerShellModuleLocalPathIdentity -Path $entryPathForRepository } else { $null }
    if ($null -eq $entryPathIdentity -or
        -not (Test-D32PowerShellModulePathWithin -Child $entryPathForRepository -Parent $repository) -or
        [StringComparer]::OrdinalIgnoreCase.Equals($entryPathIdentity, $recordRepositoryIdentity)) { return $false }
    $referenceFields = @('path','sha256','bytes','volume_serial_hex','file_id_hex')
    foreach ($referenceName in @('authority_reference','profile_reference','git_image')) {
        $script:D32PowerShellModuleAdmissionValidationContext = "record.reference.$referenceName"
        $reference = Get-D32PowerShellModuleAdmissionField -Record $Document -Name $referenceName
        if ($null -eq $reference) { return $false }
        $referenceNames = [System.Collections.Generic.List[string]]::new()
        if ($reference -is [System.Collections.IDictionary]) { foreach ($key in $reference.Keys) { $referenceNames.Add([string]$key) } }
        else { foreach ($property in $reference.PSObject.Properties) { $referenceNames.Add([string]$property.Name) } }
        if ($referenceNames.Count -ne $referenceFields.Count) { return $false }
        foreach ($field in $referenceFields) { if (-not $referenceNames.Contains($field)) { return $false } }
        $path = Get-D32PowerShellModuleAdmissionField -Record $reference -Name 'path'; $sha = Get-D32PowerShellModuleAdmissionField -Record $reference -Name 'sha256'; $bytes = Get-D32PowerShellModuleAdmissionField -Record $reference -Name 'bytes'
        $volume = Get-D32PowerShellModuleAdmissionField -Record $reference -Name 'volume_serial_hex'; $fileId = Get-D32PowerShellModuleAdmissionField -Record $reference -Name 'file_id_hex'
        if ($path -isnot [string] -or -not [IO.Path]::IsPathRooted($path) -or [IO.Path]::GetFullPath($path) -cne $path -or
            $sha -isnot [string] -or $sha -cnotmatch '^[0-9a-f]{64}$' -or
            -not ($bytes -is [int32] -or $bytes -is [int64] -or $bytes -is [uint32] -or $bytes -is [uint64]) -or [Int64]$bytes -le 0 -or
            $volume -isnot [string] -or $volume -cnotmatch '^[0-9a-f]{16}$' -or $fileId -isnot [string] -or $fileId -cnotmatch '^[0-9a-f]{32}$') { return $false }
        if ((Test-D32PowerShellModulePathWithin -Child $path -Parent $repository) -or
            (Test-D32PowerShellModulePathWithin -Child $repository -Parent $path)) { return $false }
    }
    $script:D32PowerShellModuleAdmissionValidationContext = 'record.runner-startup-and-entry'
    $hostRecord = Get-D32PowerShellModuleAdmissionField -Record $Document -Name 'powershell_host'; $runner = Get-D32PowerShellModuleAdmissionField -Record $Document -Name 'runner_process'; $startup = Get-D32PowerShellModuleAdmissionField -Record $Document -Name 'startup'
    $entry = Get-D32PowerShellModuleAdmissionField -Record $Document -Name 'entry_script_path'; $entryFile = Get-D32PowerShellModuleAdmissionField -Record $Document -Name 'entry_script'; $closure = Get-D32PowerShellModuleAdmissionField -Record $Document -Name 'module_closure'; $verification = Get-D32PowerShellModuleAdmissionField -Record $Document -Name 'import_verification'
    $script:D32PowerShellModuleAdmissionValidationContext = 'record.entry-script-canonical-path'
    if ($null -eq $hostRecord -or $null -eq $runner -or $null -eq $startup -or $entry -isnot [string] -or $null -eq $entryFile -or
        $null -eq (ConvertTo-D32PowerShellModuleLocalPathIdentity -Path $entry)) { return $false }
    $verifyNames = [System.Collections.Generic.List[string]]::new()
    if ($verification -is [System.Collections.IDictionary]) { foreach ($key in $verification.Keys) { $verifyNames.Add([string]$key) } } elseif ($null -ne $verification) { foreach ($property in $verification.PSObject.Properties) { $verifyNames.Add([string]$property.Name) } }
    if ($verifyNames.Count -ne 6 -or -not $verifyNames.Contains('state') -or -not $verifyNames.Contains('verified_import_count') -or -not $verifyNames.Contains('modules') -or -not $verifyNames.Contains('assemblies') -or -not $verifyNames.Contains('commands') -or -not $verifyNames.Contains('native_modules') -or
        (& $get $verification 'state') -cne 'VERIFIED' -or (& $get $verification 'verified_import_count') -ne 3 -or (& $get $verification 'modules') -isnot [Array] -or (& $get $verification 'modules').Count -ne 3 -or
        (& $get $verification 'assemblies') -isnot [Array] -or (& $get $verification 'assemblies').Count -eq 0 -or (& $get $verification 'commands') -isnot [Array] -or (& $get $verification 'commands').Count -eq 0 -or
        (& $get $verification 'native_modules') -isnot [Array] -or (& $get $verification 'native_modules').Count -eq 0) { return $false }
    $script:D32PowerShellModuleAdmissionValidationContext = 'record.entry-script-reference-shape'
    $entryFileNames = [System.Collections.Generic.List[string]]::new()
    if ($entryFile -is [System.Collections.IDictionary]) { foreach ($key in $entryFile.Keys) { $entryFileNames.Add([string]$key) } } else { foreach ($property in $entryFile.PSObject.Properties) { $entryFileNames.Add([string]$property.Name) } }
    if ($entryFileNames.Count -ne 5) { return $false }
    foreach ($field in $referenceFields) { if (-not $entryFileNames.Contains($field)) { return $false } }
    $script:D32PowerShellModuleAdmissionValidationContext = 'record.entry-script-reference-fields'
    if ((& $get $entryFile 'path') -cne $entry -or (& $get $entryFile 'sha256') -isnot [string] -or (& $get $entryFile 'sha256') -cnotmatch '^[0-9a-f]{64}$' -or
        -not ((& $get $entryFile 'bytes') -is [int64] -or (& $get $entryFile 'bytes') -is [int32]) -or [Int64](& $get $entryFile 'bytes') -le 0 -or
        (& $get $entryFile 'volume_serial_hex') -isnot [string] -or (& $get $entryFile 'volume_serial_hex') -cnotmatch '^[0-9a-f]{16}$' -or
        (& $get $entryFile 'file_id_hex') -isnot [string] -or (& $get $entryFile 'file_id_hex') -cnotmatch '^[0-9a-f]{32}$') { return $false }
    $entryCheckFences = [System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)
    $entryCheckSnapshot = $null
    $script:D32PowerShellModuleAdmissionValidationContext = 'record.entry-script-opened-reference'
    try {
        $entryCheckSnapshot = Open-D32PowerShellAuthorityFile -Path $entry -DirectoryFences $entryCheckFences
        foreach ($field in @('path','sha256','bytes','volume_serial_hex','file_id_hex')) {
            if ((& $get $entryFile $field) -cne $entryCheckSnapshot.Record[$field]) { return $false }
        }
    }
    catch { return $false }
    finally {
        if ($null -ne $entryCheckSnapshot -and $null -ne $entryCheckSnapshot.Stream -and -not $entryCheckSnapshot.Stream.SafeFileHandle.IsClosed) { $entryCheckSnapshot.Stream.Dispose() }
        foreach ($directoryFence in $entryCheckFences.Values) { if ($null -ne $directoryFence.Handle -and -not $directoryFence.Handle.IsClosed) { $directoryFence.Handle.Dispose() } }
    }
    $script:D32PowerShellModuleAdmissionValidationContext = 'record.powershell-host-reference'
    $hostNames = [System.Collections.Generic.List[string]]::new()
    if ($hostRecord -is [System.Collections.IDictionary]) { foreach ($key in $hostRecord.Keys) { $hostNames.Add([string]$key) } } else { foreach ($property in $hostRecord.PSObject.Properties) { $hostNames.Add([string]$property.Name) } }
    if ($hostNames.Count -ne 6) { return $false }
    foreach ($field in @('path','sha256','bytes','volume_serial_hex','file_id_hex','pshome')) { if (-not $hostNames.Contains($field)) { return $false } }
    $hostPath = & $get $hostRecord 'path'; $powerShellHome = & $get $hostRecord 'pshome'
    if ($hostPath -isnot [string] -or -not [IO.Path]::IsPathRooted($hostPath) -or $hostPath -cne [IO.Path]::GetFullPath($hostPath) -or
        $powerShellHome -isnot [string] -or -not [IO.Path]::IsPathRooted($powerShellHome) -or $powerShellHome -cne [IO.Path]::GetFullPath($powerShellHome) -or $hostPath -cne [IO.Path]::Combine($powerShellHome, 'pwsh.exe') -or
        (& $get $hostRecord 'sha256') -isnot [string] -or (& $get $hostRecord 'sha256') -cnotmatch '^[0-9a-f]{64}$' -or
        (& $get $hostRecord 'bytes') -isnot [Int64] -or [Int64](& $get $hostRecord 'bytes') -le 0 -or
        (& $get $hostRecord 'volume_serial_hex') -isnot [string] -or (& $get $hostRecord 'volume_serial_hex') -cnotmatch '^[0-9a-f]{16}$' -or
        (& $get $hostRecord 'file_id_hex') -isnot [string] -or (& $get $hostRecord 'file_id_hex') -cnotmatch '^[0-9a-f]{32}$') { return $false }
    $script:D32PowerShellModuleAdmissionValidationContext = 'record.runner-process-reference-and-token'
    $runnerNames = [System.Collections.Generic.List[string]]::new()
    if ($runner -is [System.Collections.IDictionary]) { foreach ($key in $runner.Keys) { $runnerNames.Add([string]$key) } } else { foreach ($property in $runner.PSObject.Properties) { $runnerNames.Add([string]$property.Name) } }
    if ($runnerNames.Count -ne 5) { return $false }
    foreach ($field in @('process_id','start_time_utc_ticks','image_path','image_file_id_hex','token_state')) { if (-not $runnerNames.Contains($field)) { return $false } }
    $processId = & $get $runner 'process_id'; $startTicks = & $get $runner 'start_time_utc_ticks'; $tokenState = & $get $runner 'token_state'
    if (-not ($processId -is [int32] -or $processId -is [int64]) -or [Int64]$processId -le 0 -or -not ($startTicks -is [int64] -or $startTicks -is [int32]) -or [Int64]$startTicks -le 0 -or
        (& $get $runner 'image_path') -cne $hostPath -or (& $get $runner 'image_file_id_hex') -cne (& $get $hostRecord 'file_id_hex') -or
        -not (Test-D32PowerShellAuthorityTokenRecord -Token $tokenState)) { return $false }
    $script:D32PowerShellModuleAdmissionValidationContext = 'record.startup-reference'
    $startupNames = [System.Collections.Generic.List[string]]::new()
    if ($startup -is [System.Collections.IDictionary]) { foreach ($key in $startup.Keys) { $startupNames.Add([string]$key) } } else { foreach ($property in $startup.PSObject.Properties) { $startupNames.Add([string]$property.Name) } }
    if ($startupNames.Count -ne 3) { return $false }
    foreach ($field in @('file_operand','switches','startup_policy')) { if (-not $startupNames.Contains($field)) { return $false } }
    $startupFile = & $get $startup 'file_operand'; $switches = & $get $startup 'switches'
    if ($startupFile -cne $entry -or $switches -isnot [Array] -or $switches -cnotcontains '-NoProfile' -or (& $get $startup 'startup_policy') -cne 'DIRECT_NO_PROFILE_FILE_V1') { return $false }
    $startupSeen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($switch in $switches) { if ([string]$switch -cnotin @('-NoLogo','-NoProfile','-NonInteractive') -or -not $startupSeen.Add([string]$switch)) { return $false } }
    $script:D32PowerShellModuleAdmissionValidationContext = 'record.module-closure-header'
    $closureNames = [System.Collections.Generic.List[string]]::new()
    if ($closure -is [System.Collections.IDictionary]) { foreach ($key in $closure.Keys) { $closureNames.Add([string]$key) } } elseif ($null -ne $closure) { foreach ($property in $closure.PSObject.Properties) { $closureNames.Add([string]$property.Name) } }
    if ($closureNames.Count -ne 8) { return $false }
    foreach ($field in @('module_root','module_root_volume_serial_hex','module_root_file_id_hex','inventory_sha256','modules','runtime_distribution_sha256','protected_namespace_sha256','resolver_sha256')) { if (-not $closureNames.Contains($field)) { return $false } }
    $moduleRoot = [string](& $get $closure 'module_root')
    $powerShellRoot = [IO.Path]::GetDirectoryName($moduleRoot)
    $expectedModuleRoot = [IO.Path]::GetFullPath([IO.Path]::Combine($powerShellHome, 'Modules'))
    if (-not [IO.Path]::IsPathRooted($moduleRoot) -or $moduleRoot -cne $expectedModuleRoot -or
        (& $get $closure 'module_root_volume_serial_hex') -isnot [string] -or (& $get $closure 'module_root_volume_serial_hex') -cnotmatch '^[0-9a-f]{16}$' -or
        (& $get $closure 'module_root_file_id_hex') -isnot [string] -or (& $get $closure 'module_root_file_id_hex') -cnotmatch '^[0-9a-f]{32}$') { return $false }
    $moduleRecords = & $get $closure 'modules'
    if ($moduleRecords -isnot [Array] -or $moduleRecords.Count -ne 3 -or (& $get $closure 'inventory_sha256') -cnotmatch '^[0-9a-f]{64}$' -or
        (& $get $closure 'runtime_distribution_sha256') -cnotmatch '^[0-9a-f]{64}$' -or
        (& $get $closure 'protected_namespace_sha256') -cne (& $get $closure 'runtime_distribution_sha256') -or
        (& $get $closure 'resolver_sha256') -isnot [string] -or (& $get $closure 'resolver_sha256') -cnotmatch '^[0-9a-f]{64}$') { return $false }
    $expectedNames = @('Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility','CimCmdlets')
    $expectedRoles = @('Management','Utility','CimCmdlets')
    $combinedInventory = [Text.StringBuilder]::new()
    $allClosurePaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $allClosureIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $closureFileByPath = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    for ($index = 0; $index -lt 3; $index++) {
        $script:D32PowerShellModuleAdmissionValidationContext = "record.module-closure.$($expectedRoles[$index])"
        $record = $moduleRecords[$index]
        $recordNames = [System.Collections.Generic.List[string]]::new()
        if ($record -is [System.Collections.IDictionary]) { foreach ($key in $record.Keys) { $recordNames.Add([string]$key) } } else { foreach ($property in $record.PSObject.Properties) { $recordNames.Add([string]$property.Name) } }
        if ($recordNames.Count -ne 5) { return $false }
        foreach ($field in @('role','module_name','manifest_path','inventory_sha256','files')) { if (-not $recordNames.Contains($field)) { return $false } }
        if ((& $get $record 'role') -cne $expectedRoles[$index] -or (& $get $record 'module_name') -cne $expectedNames[$index] -or
            (& $get $record 'inventory_sha256') -cnotmatch '^[0-9a-f]{64}$' -or (& $get $record 'files') -isnot [Array] -or (& $get $record 'files').Count -eq 0) { return $false }
        $manifestLeaf = if ($expectedNames[$index] -ceq 'CimCmdlets') { 'CimCmdlets.psd1' } else { $expectedNames[$index] + '.psd1' }
        $expectedManifest = [IO.Path]::GetFullPath([IO.Path]::Combine($moduleRoot, $expectedNames[$index], $manifestLeaf))
        if ((& $get $record 'manifest_path') -cne $expectedManifest) { return $false }
        $listedFiles = [System.Collections.Generic.List[object]]::new()
        $manifestIsInInventory = $false
        $allowedRootFiles = @(Get-D32PowerShellAuthorityFixedModuleClosureRootPaths -PowerShellRoot $powerShellRoot -ModuleName $expectedNames[$index])
        foreach ($file in (& $get $record 'files')) {
            if (-not (Test-D32PowerShellModuleAdmissionClosureFileRecord -FileRecord $file -Role $expectedRoles[$index] `
                -ModuleDirectory ([IO.Path]::GetFullPath([IO.Path]::Combine($moduleRoot, $expectedNames[$index]))) `
                -AllowedRootFilePaths $allowedRootFiles -SeenPaths $allClosurePaths -SeenFileIds $allClosureIds)) { return $false }
            $filePath = & $get $file 'path'; $fileSha = & $get $file 'sha256'; $fileBytes = & $get $file 'bytes'
            if ([StringComparer]::OrdinalIgnoreCase.Equals($filePath, $expectedManifest)) { $manifestIsInInventory = $true }
            $listedFiles.Add([ordered]@{ path = $filePath; bytes = [Int64]$fileBytes; sha256 = $fileSha; volume_serial_hex = [string](& $get $file 'volume_serial_hex'); file_id_hex = [string](& $get $file 'file_id_hex') })
            $closureFileByPath.Add($filePath, $file)
        }
        if (-not $manifestIsInInventory) { return $false }
        if ((Get-D32PowerShellAuthorityInventoryDigest -Role $expectedRoles[$index] -Files $listedFiles.ToArray()) -cne (& $get $record 'inventory_sha256')) { return $false }
        [void]$combinedInventory.Append($expectedRoles[$index]).Append('|').Append([string](& $get $record 'inventory_sha256')).Append("`n")
    }
    $expectedCombined = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes($combinedInventory.ToString()))).ToLowerInvariant()
    $script:D32PowerShellModuleAdmissionValidationContext = 'record.module-closure-combined-digest'
    if ((& $get $closure 'inventory_sha256') -cne $expectedCombined) { return $false }
    $resolver = & $get $Document 'resolver_admission'
    $resolverNames = [System.Collections.Generic.List[string]]::new()
    if ($resolver -is [System.Collections.IDictionary]) { foreach ($key in $resolver.Keys) { $resolverNames.Add([string]$key) } } elseif ($null -ne $resolver) { foreach ($property in $resolver.PSObject.Properties) { $resolverNames.Add([string]$property.Name) } }
    $resolverFields = @('state','policy_id','resolver_sha256','os_security_inventory_sha256','native_policy','module_search_path','trusted_platform_paths','loaded_managed_assembly_paths','deps_paths','native_directories','native_module_paths','active_environment')
    $script:D32PowerShellModuleAdmissionValidationContext = 'record.resolver-admission-shape'
    if ($resolverNames.Count -ne $resolverFields.Count) { return $false }
    foreach ($field in $resolverFields) { if (-not $resolverNames.Contains($field)) { return $false } }
    $resolverGet = $get
    $script:D32PowerShellModuleAdmissionValidationContext = 'record.resolver-admission-fixed-policy-and-digest'
    if ((& $resolverGet $resolver 'state') -cne 'VERIFIED' -or (& $resolverGet $resolver 'policy_id') -cne 'D32_POWERSHELL_RESOLVER_DOMAIN_V2' -or
        (& $resolverGet $resolver 'native_policy') -cne 'LOAD_LIBRARY_SEARCH_APPLICATION_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32; SetDllDirectoryW(NULL); verified in current process' -or
        (& $resolverGet $resolver 'module_search_path') -cne [IO.Path]::GetFullPath([IO.Path]::Combine($powerShellHome,'Modules')) -or
        (& $resolverGet $resolver 'os_security_inventory_sha256') -isnot [string] -or (& $resolverGet $resolver 'os_security_inventory_sha256') -cnotmatch '^[0-9a-f]{64}$' -or
        (& $resolverGet $resolver 'resolver_sha256') -isnot [string] -or (& $resolverGet $resolver 'resolver_sha256') -cnotmatch '^[0-9a-f]{64}$' -or
        (& $resolverGet $resolver 'resolver_sha256') -cne (& $get $closure 'resolver_sha256')) { return $false }
    $windowsRoot = Get-D32PowerShellAuthorityWindowsRootPath
    $defenderPlatformRoot = 'C:\ProgramData\Microsoft\Windows Defender\Platform'
    foreach ($field in @('trusted_platform_paths','loaded_managed_assembly_paths','deps_paths','native_directories','native_module_paths')) {
        $script:D32PowerShellModuleAdmissionValidationContext = "record.resolver-paths.$field"
        $array = & $resolverGet $resolver $field
        if ($array -isnot [Array] -or $array.Count -eq 0) { return $false }
        $previous = ''
        foreach ($path in $array) {
            $underPowerShell = $path -is [string] -and (Test-D32PowerShellAuthorityPathWithin -Child $path -Parent $powerShellHome)
            $underWindows = $path -is [string] -and (Test-D32PowerShellAuthorityPathWithin -Child $path -Parent $windowsRoot)
            $underDefender = $field -ceq 'native_module_paths' -and $path -is [string] -and (Test-D32PowerShellAuthorityPathWithin -Child $path -Parent $defenderPlatformRoot)
            $validDomain = if ($field -ceq 'native_module_paths') { $underPowerShell -or $underWindows -or $underDefender } else { $underPowerShell -or $underWindows }
            if ($path -isnot [string] -or -not [IO.Path]::IsPathRooted($path) -or [IO.Path]::GetFullPath($path) -cne $path -or
                -not $validDomain -or
                ($previous.Length -gt 0 -and [StringComparer]::OrdinalIgnoreCase.Compare($previous,$path) -ge 0)) { return $false }
            $previous = $path
        }
    }
    $script:D32PowerShellModuleAdmissionValidationContext = 'record.resolver-active-environment-empty-array'
    $activeEnvironment = & $resolverGet $resolver 'active_environment'
    if ($activeEnvironment -isnot [Array] -or $activeEnvironment.Count -ne 0) { return $false }
    $nativeComponentByPath = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($nativeRecord in (& $get $verification 'native_modules')) {
        $script:D32PowerShellModuleAdmissionValidationContext = 'record.resolver-native-origin-index'
        $nativeRecordNames = [System.Collections.Generic.List[string]]::new()
        if ($nativeRecord -is [System.Collections.IDictionary]) { foreach ($key in $nativeRecord.Keys) { $nativeRecordNames.Add([string]$key) } } elseif ($null -ne $nativeRecord) { foreach ($property in $nativeRecord.PSObject.Properties) { $nativeRecordNames.Add([string]$property.Name) } }
        if ($nativeRecordNames.Count -ne 9 -or -not $nativeRecordNames.Contains('path') -or -not $nativeRecordNames.Contains('component_type')) { return $false }
        $nativePath = & $get $nativeRecord 'path'; $componentType = & $get $nativeRecord 'component_type'
        if ($nativePath -isnot [string] -or -not [IO.Path]::IsPathRooted($nativePath) -or [IO.Path]::GetFullPath($nativePath) -cne $nativePath -or
            $componentType -isnot [string] -or $componentType -cnotin @('POWERSHELL_DISTRIBUTION','MICROSOFT_WINDOWS_OS_INSTALLATION','MICROSOFT_WINDOWS_DEFENDER_PLATFORM') -or
            -not $nativeComponentByPath.TryAdd($nativePath, $componentType)) { return $false }
    }
    $nativePathsForDigest = & $resolverGet $resolver 'native_module_paths'
    if ($nativeComponentByPath.Count -ne $nativePathsForDigest.Count) { return $false }
    foreach ($nativePath in $nativePathsForDigest) {
        $script:D32PowerShellModuleAdmissionValidationContext = 'record.resolver-native-origin-set-equality'
        if (-not $nativeComponentByPath.ContainsKey([string]$nativePath)) { return $false }
    }
    $script:D32PowerShellModuleAdmissionValidationContext = 'record.resolver-native-origin-digest'
    $resolverDigests = Get-D32PowerShellAuthorityResolverDigestSet -ModuleSearchPath ([string](& $resolverGet $resolver 'module_search_path')) `
        -OsSecurityInventorySha256 ([string](& $resolverGet $resolver 'os_security_inventory_sha256')) `
        -TrustedPlatformPaths ([string[]](& $resolverGet $resolver 'trusted_platform_paths')) -DepsPaths ([string[]](& $resolverGet $resolver 'deps_paths')) `
        -NativeDirectories ([string[]](& $resolverGet $resolver 'native_directories')) -NativeModulePaths ([string[]]$nativePathsForDigest) `
        -ActiveEnvironment ([object[]]$activeEnvironment) -NativePolicy ([string](& $resolverGet $resolver 'native_policy')) -NativeFileComponents $nativeComponentByPath
    if ($resolverDigests.ResolverSha256 -cne [string](& $resolverGet $resolver 'resolver_sha256')) { return $false }
    $observedModules = & $get $verification 'modules'
    $allowedModulePaths = @{}
    $roles = @(Get-D32PowerShellAuthorityFixedModuleRoles -PowerShellRoot $powerShellRoot)
    $observedModuleNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    for ($index = 0; $index -lt 3; $index++) {
        $script:D32PowerShellModuleAdmissionValidationContext = "record.actual-module.$($expectedRoles[$index])"
        $allowedModulePaths[$expectedNames[$index]] = @(Get-D32PowerShellAuthorityAllowedModulePaths -PowerShellRoot $powerShellRoot -Role $roles[$index])
    }
    foreach ($module in $observedModules) {
        $moduleFields = [System.Collections.Generic.List[string]]::new()
        if ($module -is [System.Collections.IDictionary]) { foreach ($key in $module.Keys) { $moduleFields.Add([string]$key) } } else { foreach ($property in $module.PSObject.Properties) { $moduleFields.Add([string]$property.Name) } }
        if ($moduleFields.Count -ne 3 -or -not $moduleFields.Contains('name') -or -not $moduleFields.Contains('path') -or -not $moduleFields.Contains('version')) { return $false }
        $name = [string](& $get $module 'name'); $path = [string](& $get $module 'path'); $versionText = [string](& $get $module 'version')
        if (-not $allowedModulePaths.ContainsKey($name) -or $path -cnotin $allowedModulePaths[$name] -or [String]::IsNullOrWhiteSpace($versionText) -or -not $observedModuleNames.Add($name)) { return $false }
    }
    $fileRecordsByPath = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($record in $moduleRecords) { foreach ($file in (& $get $record 'files')) { $fileRecordsByPath[[string](& $get $file 'path')] = $file } }
    $assemblyPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($assembly in (& $get $verification 'assemblies')) {
        if (-not (Test-D32PowerShellModuleAdmissionAssemblyOriginRecord -AssemblyRecord $assembly `
            -FileRecordsByPath $fileRecordsByPath -SeenAssemblyPaths $assemblyPaths)) { return $false }
    }
    foreach ($requiredAssemblyPath in (Get-D32PowerShellAuthorityFixedImportAssemblyPaths -PowerShellRoot $powerShellRoot)) {
        $script:D32PowerShellModuleAdmissionValidationContext = 'record.required-import-assembly-closure'
        if (-not $assemblyPaths.Contains([IO.Path]::GetFullPath([string]$requiredAssemblyPath))) { return $false }
    }
    $nativeModulePaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $nativeExpected = [System.Collections.Generic.List[string]]::new()
    foreach ($path in (& $resolverGet $resolver 'native_module_paths')) { $nativeExpected.Add([string]$path) }
    $windowsRoot = Get-D32PowerShellAuthorityWindowsRootPath
    $defenderPlatformRoot = 'C:\ProgramData\Microsoft\Windows Defender\Platform'
    $trustedWriterSids = @('S-1-5-18','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464','S-1-5-32-544')
    $nativeObservedSorted = [System.Collections.Generic.List[string]]::new()
    foreach ($nativeModule in (& $get $verification 'native_modules')) {
        $script:D32PowerShellModuleAdmissionValidationContext = 'record.actual-native-origin-content-and-source'
        $nativeFields = [System.Collections.Generic.List[string]]::new()
        if ($nativeModule -is [System.Collections.IDictionary]) { foreach ($key in $nativeModule.Keys) { $nativeFields.Add([string]$key) } } else { foreach ($property in $nativeModule.PSObject.Properties) { $nativeFields.Add([string]$property.Name) } }
        if ($nativeFields.Count -ne 9) { return $false }
        foreach ($field in @('path','source','component_type','bytes','sha256','volume_serial_hex','file_id_hex','owner_sid','security_descriptor_sha256')) { if (-not $nativeFields.Contains($field)) { return $false } }
        $path = [string](& $get $nativeModule 'path'); $source = [string](& $get $nativeModule 'source'); $componentType = [string](& $get $nativeModule 'component_type')
        $bytes = & $get $nativeModule 'bytes'; $sha = [string](& $get $nativeModule 'sha256'); $volume = [string](& $get $nativeModule 'volume_serial_hex'); $fileId = [string](& $get $nativeModule 'file_id_hex')
        $owner = [string](& $get $nativeModule 'owner_sid'); $aclHash = [string](& $get $nativeModule 'security_descriptor_sha256')
        if (-not [IO.Path]::IsPathRooted($path) -or [IO.Path]::GetFullPath($path) -cne $path -or -not $nativeModulePaths.Add($path) -or
            -not ($bytes -is [int32] -or $bytes -is [int64] -or $bytes -is [uint32] -or $bytes -is [uint64]) -or [Int64]$bytes -le 0 -or
            $sha -cnotmatch '^[0-9a-f]{64}$' -or $volume -cnotmatch '^[0-9a-f]{16}$' -or $fileId -cnotmatch '^[0-9a-f]{32}$' -or
            $owner -cnotin $trustedWriterSids -or $aclHash -cnotmatch '^[0-9a-f]{64}$') { return $false }
        if ($source -ceq 'PSHOME_DISTRIBUTION') {
            if ($componentType -cne 'POWERSHELL_DISTRIBUTION' -or -not (Test-D32PowerShellAuthorityPathWithin -Child $path -Parent $powerShellHome)) { return $false }
        }
        elseif ($source -ceq 'WINDOWS_OS_COMPONENT') {
            if ($componentType -cne 'MICROSOFT_WINDOWS_OS_INSTALLATION' -or -not (Test-D32PowerShellAuthorityPathWithin -Child $path -Parent $windowsRoot)) { return $false }
        }
        elseif ($source -ceq 'DEFENDER_PLATFORM_COMPONENT') {
            if ($componentType -cne 'MICROSOFT_WINDOWS_DEFENDER_PLATFORM' -or -not (Test-D32PowerShellAuthorityPathWithin -Child $path -Parent $defenderPlatformRoot)) { return $false }
        }
        else { return $false }
        $nativeObservedSorted.Add($path)
    }
    $script:D32PowerShellModuleAdmissionValidationContext = 'record.actual-native-origin-order-and-cardinality'
    if ($nativeExpected.Count -ne $nativeObservedSorted.Count) { return $false }
    for ($index = 0; $index -lt $nativeExpected.Count; $index++) { if ($nativeExpected[$index] -cne $nativeObservedSorted[$index]) { return $false } }
    $commandKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($command in (& $get $verification 'commands')) {
        $script:D32PowerShellModuleAdmissionValidationContext = 'record.actual-command-origin'
        $commandFields = [System.Collections.Generic.List[string]]::new()
        if ($command -is [System.Collections.IDictionary]) { foreach ($key in $command.Keys) { $commandFields.Add([string]$key) } } else { foreach ($property in $command.PSObject.Properties) { $commandFields.Add([string]$property.Name) } }
        if ($commandFields.Count -ne 5) { return $false }
        foreach ($field in @('module_name','command_name','module_path','effective_module_name','effective_module_path')) { if (-not $commandFields.Contains($field)) { return $false } }
        $moduleName = [string](& $get $command 'module_name'); $commandName = [string](& $get $command 'command_name'); $modulePath = [string](& $get $command 'module_path')
        $effectiveName = [string](& $get $command 'effective_module_name'); $effectivePath = [string](& $get $command 'effective_module_path')
        if (-not $allowedModulePaths.ContainsKey($moduleName) -or $modulePath -cnotin $allowedModulePaths[$moduleName] -or
            -not $allowedModulePaths.ContainsKey($effectiveName) -or $effectivePath -cnotin $allowedModulePaths[$effectiveName] -or
            [String]::IsNullOrWhiteSpace($commandName) -or -not $commandKeys.Add($moduleName + '|' + $commandName)) { return $false }
    }
    if ($null -ne $ExpectedContext) {
        foreach ($field in @('authority_reference','profile_reference','git_image','powershell_host','module_import_order','module_closure','resolver_admission','import_verification','import_attempts')) {
            $script:D32PowerShellModuleAdmissionValidationContext = "record.expected-context.$field"
            $actualContextValue = & $get $Document $field
            $expectedContextValue = & $get $ExpectedContext $field
            if ((ConvertTo-D32PowerShellAuthorityJsonText -Value $actualContextValue) -cne (ConvertTo-D32PowerShellAuthorityJsonText -Value $expectedContextValue)) { return $false }
        }
    }
    return $true
}

function Get-D32PowerShellModuleProducerEntryPaths {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)]
        [ValidateSet('fixture_provenance','inventory_discovery','inventory_baseline','phase0_matrix','release_attestation','post_bundle_aggregate')]
        [string]$ProducerRole
    )
    $repo = ConvertTo-D32PowerShellModuleLocalPathIdentity -Path $Repository
    if ($null -eq $repo) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: producer repository path must be a canonical local non-reparse path' }
    $scripts = [IO.Path]::Combine($repo, 'scripts')
    $names = switch ($ProducerRole) {
        'fixture_provenance' { @('d32-fixture-prebuild.ps1','d32-phase0-matrix.ps1','d32-preflight.ps1') }
        'inventory_discovery' { @('d32-test-inventory-discovery.ps1','d32-preflight.ps1') }
        'inventory_baseline' { @('d32-test-inventory-baseline.ps1','d32-preflight.ps1') }
        'phase0_matrix' { @('d32-phase0-matrix.ps1','d32-preflight.ps1') }
        'release_attestation' { @('d32-preflight.ps1') }
        'post_bundle_aggregate' { @('d32-preflight.ps1') }
    }
    return @($names | ForEach-Object { [IO.Path]::GetFullPath([IO.Path]::Combine($scripts, [string]$_)) })
}

function ConvertTo-D32PowerShellModuleLocalPathIdentity {
    param([AllowNull()][string]$Path)
    try {
        # Admission records retain their exact startup and opened-file paths.
        # This comparison-only projection collapses just the Win32 extended
        # prefix for canonical local DOS-drive paths, after rejecting traversal,
        # UNC/device namespaces and every reparse component. File/object identity
        # is still reopened and compared by Test-D32PowerShellModuleAdmissionRecord.
        if ([String]::IsNullOrWhiteSpace($Path) -or $Path.Contains('/')) { return $null }
        $ordinary = $Path
        if ($ordinary.StartsWith('\\?\UNC\', [StringComparison]::OrdinalIgnoreCase)) { return $null }
        if ($ordinary.StartsWith('\\?\', [StringComparison]::Ordinal)) { $ordinary = $ordinary.Substring(4) }
        elseif ($ordinary.StartsWith('\\', [StringComparison]::Ordinal) -or $ordinary.StartsWith('\\.\', [StringComparison]::Ordinal)) { return $null }
        if ($ordinary -notmatch '^[A-Za-z]:\\' -or $ordinary.Length -le 3 -or $ordinary.Substring(2).Contains(':')) { return $null }
        foreach ($part in @($ordinary.Substring(3) -split '\\')) {
            if ([String]::IsNullOrWhiteSpace($part) -or $part -ceq '.' -or $part -ceq '..' -or $part.EndsWith('.') -or $part.EndsWith(' ')) { return $null }
        }
        if ([IO.Path]::GetFullPath($ordinary) -cne $ordinary -or -not (Test-D32PowerShellAuthorityPathNoReparse -Path $ordinary)) { return $null }
        return $ordinary
    }
    catch { return $null }
}

function Test-D32PowerShellModulePathIdentityEqual {
    param([AllowNull()][string]$Left, [AllowNull()][string]$Right)
    $leftIdentity = ConvertTo-D32PowerShellModuleLocalPathIdentity -Path $Left
    $rightIdentity = ConvertTo-D32PowerShellModuleLocalPathIdentity -Path $Right
    return $null -ne $leftIdentity -and $null -ne $rightIdentity -and
        [StringComparer]::OrdinalIgnoreCase.Equals($leftIdentity, $rightIdentity)
}

function Test-D32PowerShellModulePathWithin {
    param([AllowNull()][string]$Child, [AllowNull()][string]$Parent)
    $childIdentity = ConvertTo-D32PowerShellModuleLocalPathIdentity -Path $Child
    $parentIdentity = ConvertTo-D32PowerShellModuleLocalPathIdentity -Path $Parent
    if ($null -eq $childIdentity -or $null -eq $parentIdentity) { return $false }
    return Test-D32PowerShellAuthorityPathWithin -Child $childIdentity -Parent $parentIdentity
}

function Test-D32PowerShellModuleProducerContextEqual {
    param([AllowNull()][object]$Document, [AllowNull()][object]$ExpectedContext)
    try {
        if ($null -eq $Document -or $null -eq $ExpectedContext) { return $false }
        foreach ($field in @('runner_process','startup','entry_script_path','entry_script')) {
            $actualValue = if ($Document -is [System.Collections.IDictionary]) { $Document[$field] } else { $Document.PSObject.Properties[$field].Value }
            $expectedValue = if ($ExpectedContext -is [System.Collections.IDictionary]) { $ExpectedContext[$field] } else { $ExpectedContext.PSObject.Properties[$field].Value }
            if ($null -eq $actualValue -or $null -eq $expectedValue -or
                (ConvertTo-D32PowerShellAuthorityJsonText -Value $actualValue) -cne (ConvertTo-D32PowerShellAuthorityJsonText -Value $expectedValue)) { return $false }
        }
        return $true
    }
    catch { return $false }
}

function Test-D32PowerShellModuleProducerProcessDistinct {
    param([AllowNull()][object]$Document, [AllowNull()][object]$OtherAdmission)
    try {
        if ($null -eq $Document -or $null -eq $OtherAdmission) { return $false }
        $left = if ($Document -is [System.Collections.IDictionary]) { $Document['runner_process'] } else { $Document.PSObject.Properties['runner_process'].Value }
        $right = if ($OtherAdmission -is [System.Collections.IDictionary]) { $OtherAdmission['runner_process'] } else { $OtherAdmission.PSObject.Properties['runner_process'].Value }
        if ($null -eq $left -or $null -eq $right) { return $false }
        return ([Int64]$left.process_id -ne [Int64]$right.process_id) -or ([Int64]$left.start_time_utc_ticks -ne [Int64]$right.start_time_utc_ticks)
    }
    catch { return $false }
}

function Test-D32PowerShellModuleAdmissionProducerBinding {
    param(
        [AllowNull()][object]$Document,
        [Parameter(Mandatory = $true)][string]$CandidateSha,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)]
        [ValidateSet('fixture_provenance','inventory_discovery','inventory_baseline','phase0_matrix','release_attestation','post_bundle_aggregate')]
        [string]$ProducerRole,
        [AllowNull()][object]$ExpectedAdmissionContext,
        [AllowNull()][object]$ExpectedProducerContext,
        [AllowNull()][object]$ExactLinkedAdmission,
        [AllowNull()][object]$DistinctFromAdmission
    )
    try {
        $script:D32PowerShellModuleAdmissionValidationContext = 'producer.admission-record'
        if (-not (Test-D32PowerShellModuleAdmissionRecord -Document $Document -CandidateSha $CandidateSha -Repository $Repository -ExpectedContext $ExpectedAdmissionContext)) { return $false }
        return Test-D32PowerShellModuleAdmissionProducerContextBinding -Document $Document -Repository $Repository -ProducerRole $ProducerRole `
            -ExpectedProducerContext $ExpectedProducerContext -ExactLinkedAdmission $ExactLinkedAdmission -DistinctFromAdmission $DistinctFromAdmission
    }
    catch { return $false }
}

function Test-D32PowerShellModuleAdmissionProducerContextBinding {
    param(
        [AllowNull()][object]$Document,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)]
        [ValidateSet('fixture_provenance','inventory_discovery','inventory_baseline','phase0_matrix','release_attestation','post_bundle_aggregate')]
        [string]$ProducerRole,
        [AllowNull()][object]$ExpectedProducerContext,
        [AllowNull()][object]$ExactLinkedAdmission,
        [AllowNull()][object]$DistinctFromAdmission
    )
    try {
        if ($null -eq $Document) {
            $script:D32PowerShellModuleAdmissionValidationContext = 'producer.document'
            return $false
        }
        $script:D32PowerShellModuleAdmissionValidationContext = 'producer.role-entry-path'
        if ($Document.entry_script_path -isnot [string]) { return $false }
        $entryPath = [string]$Document.entry_script_path
        $rolePaths = @(Get-D32PowerShellModuleProducerEntryPaths -Repository $Repository -ProducerRole $ProducerRole)
        $roleMatch = $false
        foreach ($path in $rolePaths) {
            if (Test-D32PowerShellModulePathIdentityEqual -Left $entryPath -Right ([string]$path)) { $roleMatch = $true; break }
        }
        if (-not $roleMatch) { return $false }
        $script:D32PowerShellModuleAdmissionValidationContext = 'producer.startup-file-operand'
        if (-not [StringComparer]::OrdinalIgnoreCase.Equals([string]$Document.startup.file_operand, $entryPath)) { return $false }
        if ($null -ne $ExpectedProducerContext) {
            $script:D32PowerShellModuleAdmissionValidationContext = 'producer.expected-process-startup-entry-context'
            if (-not (Test-D32PowerShellModuleProducerContextEqual -Document $Document -ExpectedContext $ExpectedProducerContext)) { return $false }
        }
        if ($null -ne $ExactLinkedAdmission -and
            (ConvertTo-D32PowerShellAuthorityJsonText -Value $Document) -cne (ConvertTo-D32PowerShellAuthorityJsonText -Value $ExactLinkedAdmission)) {
            $script:D32PowerShellModuleAdmissionValidationContext = 'producer.exact-linked-admission'
            return $false
        }
        if ($null -ne $DistinctFromAdmission) {
            $script:D32PowerShellModuleAdmissionValidationContext = 'producer.distinct-process-identity'
            if (-not (Test-D32PowerShellModuleProducerProcessDistinct -Document $Document -OtherAdmission $DistinctFromAdmission)) { return $false }
        }
        $script:D32PowerShellModuleAdmissionValidationContext = 'producer.verified'
        return $true
    }
    catch { return $false }
}

function Test-D32PowerShellModuleAdmissionProfileBinding {
    param([AllowNull()][object]$Document, [AllowNull()][object]$ExpectedProfileReference)
    try {
        $script:D32PowerShellModuleAdmissionValidationDetail = $null
        $script:D32PowerShellModuleAdmissionValidationContext = 'profile.document'
        if ($null -eq $Document -or $null -eq $ExpectedProfileReference) {
            $script:D32PowerShellModuleAdmissionValidationDetail = [ordered]@{ actual_is_null = ($null -eq $Document); expected_is_null = ($null -eq $ExpectedProfileReference) }
            return $false
        }
        $script:D32PowerShellModuleAdmissionValidationContext = 'profile.actual-reference'
        $actual = $Document.profile_reference
        $fields = @('path','sha256','bytes','volume_serial_hex','file_id_hex')
        foreach ($referenceIndex in 0..1) {
            $referenceKind = if ($referenceIndex -eq 0) { 'actual' } else { 'expected' }
            $reference = if ($referenceIndex -eq 0) { $actual } else { $ExpectedProfileReference }
            $script:D32PowerShellModuleAdmissionValidationContext = "profile.$referenceKind-reference-shape"
            if ($null -eq $reference) {
                $script:D32PowerShellModuleAdmissionValidationDetail = [ordered]@{ reference = $referenceKind; is_null = $true; expected_fields = $fields }
                return $false
            }
            $names = if ($reference -is [System.Collections.IDictionary]) { @($reference.Keys | ForEach-Object { [string]$_ }) } else { @($reference.PSObject.Properties | ForEach-Object { [string]$_.Name }) }
            if ($names.Count -ne $fields.Count -or @($fields | Where-Object { $_ -cnotin $names }).Count -gt 0) {
                $script:D32PowerShellModuleAdmissionValidationDetail = [ordered]@{ reference = $referenceKind; actual_fields = @($names); expected_fields = $fields }
                return $false
            }
        }
        foreach ($field in $fields) {
            $script:D32PowerShellModuleAdmissionValidationContext = "profile.reference.$field"
            $left = if ($actual -is [System.Collections.IDictionary]) { $actual[$field] } else { $actual.PSObject.Properties[$field].Value }
            $right = if ($ExpectedProfileReference -is [System.Collections.IDictionary]) { $ExpectedProfileReference[$field] } else { $ExpectedProfileReference.PSObject.Properties[$field].Value }
            $matches = if ($field -ceq 'bytes') { [Int64]$left -eq [Int64]$right } else { [string]$left -ceq [string]$right }
            if (-not $matches) {
                $script:D32PowerShellModuleAdmissionValidationDetail = [ordered]@{
                    field = $field
                    actual_type = if ($null -eq $left) { '<null>' } else { $left.GetType().FullName }
                    actual_value = $left
                    expected_type = if ($null -eq $right) { '<null>' } else { $right.GetType().FullName }
                    expected_value = $right
                }
                return $false
            }
        }
        $script:D32PowerShellModuleAdmissionValidationContext = 'profile.verified'
        return $true
    }
    catch {
        $script:D32PowerShellModuleAdmissionValidationContext = 'profile.exception'
        $script:D32PowerShellModuleAdmissionValidationDetail = [ordered]@{ exception_type = $_.Exception.GetType().FullName; message = $_.Exception.Message }
        return $false
    }
}

function Test-D32PowerShellModuleAdmissionProfileRecordBinding {
    param([AllowNull()][object]$Document, [AllowNull()][object]$ProfileRecord)
    try {
        $script:D32PowerShellModuleAdmissionValidationContext = 'profile.profile-record'
        $script:D32PowerShellModuleAdmissionValidationDetail = $null
        if ($null -eq $ProfileRecord) {
            $script:D32PowerShellModuleAdmissionValidationDetail = [ordered]@{ profile_record_is_null = $true }
            return $false
        }
        # Profile-bearing records have two frozen wire shapes: discovery and
        # Phase0/release keep the full profile with nested file_identity, while
        # the baseline intentionally carries a compact flattened reference.
        # Under StrictMode, probing a missing PSCustomObject/IDictionary member
        # with dot notation throws before the flattened case can be selected.
        $hasNestedFileIdentity = $false
        if ($ProfileRecord -is [System.Collections.IDictionary]) {
            $hasNestedFileIdentity = $ProfileRecord.Contains('file_identity')
        }
        else {
            $hasNestedFileIdentity = $null -ne $ProfileRecord.PSObject.Properties['file_identity']
        }
        if ($hasNestedFileIdentity) {
            $identity = Get-D32PowerShellModuleAdmissionField -Record $ProfileRecord -Name 'file_identity'
            if ($null -eq $identity) {
                $script:D32PowerShellModuleAdmissionValidationContext = 'profile.profile-record.nested-identity'
                $script:D32PowerShellModuleAdmissionValidationDetail = [ordered]@{ profile_record_shape = 'nested-file-identity'; file_identity_is_null = $true }
                return $false
            }
            $reference = [ordered]@{
                path = [string](Get-D32PowerShellModuleAdmissionField -Record $ProfileRecord -Name 'path')
                sha256 = [string](Get-D32PowerShellModuleAdmissionField -Record $ProfileRecord -Name 'sha256')
                bytes = [Int64](Get-D32PowerShellModuleAdmissionField -Record $identity -Name 'bytes')
                volume_serial_hex = [string](Get-D32PowerShellModuleAdmissionField -Record $identity -Name 'volume_serial_hex')
                file_id_hex = [string](Get-D32PowerShellModuleAdmissionField -Record $identity -Name 'file_id_hex')
            }
        }
        else {
            $reference = [ordered]@{
                path = [string](Get-D32PowerShellModuleAdmissionField -Record $ProfileRecord -Name 'path')
                sha256 = [string](Get-D32PowerShellModuleAdmissionField -Record $ProfileRecord -Name 'sha256')
                bytes = [Int64](Get-D32PowerShellModuleAdmissionField -Record $ProfileRecord -Name 'bytes')
                volume_serial_hex = [string](Get-D32PowerShellModuleAdmissionField -Record $ProfileRecord -Name 'volume_serial_hex')
                file_id_hex = [string](Get-D32PowerShellModuleAdmissionField -Record $ProfileRecord -Name 'file_id_hex')
            }
        }
        $script:D32PowerShellModuleAdmissionValidationDetail = [ordered]@{
            profile_record_shape = if ($hasNestedFileIdentity) { 'nested-file-identity' } else { 'flattened-file-identity' }
            profile_record_reference = $reference
        }
        $isBound = Test-D32PowerShellModuleAdmissionProfileBinding -Document $Document -ExpectedProfileReference $reference
        if ($isBound) { $script:D32PowerShellModuleAdmissionValidationDetail = $null }
        return $isBound
    }
    catch {
        $script:D32PowerShellModuleAdmissionValidationContext = 'profile.profile-record-exception'
        $script:D32PowerShellModuleAdmissionValidationDetail = [ordered]@{ exception_type = $_.Exception.GetType().FullName; message = $_.Exception.Message }
        return $false
    }
}

function Test-D32PowerShellModuleAdmissionRunnerBinding {
    param([AllowNull()][object]$Document, [Parameter(Mandatory = $true)][Int64]$ExpectedProcessId)
    try {
        return $null -ne $Document -and [Int64]$Document.runner_process.process_id -eq $ExpectedProcessId
    }
    catch { return $false }
}

function Get-D32PowerShellModuleAdmissionValidationContext {
    return [string]$script:D32PowerShellModuleAdmissionValidationContext
}

function Get-D32PowerShellModuleAdmissionValidationDetail {
    if ($null -eq $script:D32PowerShellModuleAdmissionValidationDetail) { return $null }
    return $script:D32PowerShellModuleAdmissionValidationDetail
}

function New-D32PowerShellModuleSelfTestAdmissionLease {
    param([Parameter(Mandatory = $true)][object]$State)
    if ($null -eq $State -or $null -eq $State.Admission) {
        throw 'POWERSHELL_MODULE_SELFTEST_CONTEXT_BLOCKED: an admitted state is required before installing a synthetic context'
    }
    return [PSCustomObject]@{
        State = $State
        PreviousAdmission = $State.Admission
        Active = $false
    }
}

function Set-D32PowerShellModuleSelfTestAdmission {
    param(
        [Parameter(Mandatory = $true)][object]$Lease,
        [Parameter(Mandatory = $true)][object]$Admission
    )
    if ($null -eq $Lease.State -or $null -eq $Lease.PreviousAdmission -or $Lease.Active -isnot [bool] -or $Lease.Active) {
        throw 'POWERSHELL_MODULE_SELFTEST_CONTEXT_BLOCKED: synthetic admission lease is malformed or already active'
    }
    # Mark the lease before changing shared state so a terminating interruption
    # between these operations still takes the normal restoration path.
    $Lease.Active = $true
    $Lease.State.Admission = $Admission
}

function Restore-D32PowerShellModuleSelfTestAdmission {
    param([Parameter(Mandatory = $true)][object]$Lease)
    if ($null -eq $Lease.State -or $null -eq $Lease.PreviousAdmission -or $Lease.Active -isnot [bool]) {
        throw 'POWERSHELL_MODULE_SELFTEST_CONTEXT_BLOCKED: synthetic admission lease cannot be restored'
    }
    if ($Lease.Active) {
        $Lease.State.Admission = $Lease.PreviousAdmission
        $Lease.Active = $false
    }
}

function Test-D32PowerShellModuleSelfTestAdmissionImmediateFailureRecovery {
    param(
        [Parameter(Mandatory = $true)][object]$PriorAdmission,
        [Parameter(Mandatory = $true)][object]$SyntheticAdmission
    )
    $probeState = [PSCustomObject]@{ Admission = $PriorAdmission }
    $lease = New-D32PowerShellModuleSelfTestAdmissionLease -State $probeState
    $expectedFailureObserved = $false
    $syntheticInstalledBeforeFailure = $false
    try {
        Set-D32PowerShellModuleSelfTestAdmission -Lease $lease -Admission $SyntheticAdmission
        $syntheticInstalledBeforeFailure = [object]::ReferenceEquals($probeState.Admission, $SyntheticAdmission)
        throw 'D32_SELFTEST_EXPECTED_SYNTHETIC_CONTEXT_FAILURE'
    }
    catch {
        $expectedFailureObserved = $_.Exception.Message -ceq 'D32_SELFTEST_EXPECTED_SYNTHETIC_CONTEXT_FAILURE'
    }
    finally {
        Restore-D32PowerShellModuleSelfTestAdmission -Lease $lease
    }
    return $expectedFailureObserved -and $syntheticInstalledBeforeFailure -and -not $lease.Active -and
        [object]::ReferenceEquals($probeState.Admission, $PriorAdmission)
}

function ConvertTo-D32PowerShellAuthorityJsonText {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [string]) { return [System.Text.Json.JsonSerializer]::Serialize([string]$Value, [type][string], [System.Text.Json.JsonSerializerOptions]::new()) }
    if ($Value -is [bool]) { return ([string]$Value).ToLowerInvariant() }
    if ($Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or $Value -is [uint16] -or $Value -is [int32] -or $Value -is [uint32] -or $Value -is [int64] -or $Value -is [uint64]) {
        return [Convert]::ToString($Value, [Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $parts = [System.Collections.Generic.List[string]]::new()
        foreach ($key in $Value.Keys) { $parts.Add(([System.Text.Json.JsonSerializer]::Serialize([string]$key, [type][string], [System.Text.Json.JsonSerializerOptions]::new()) + ':' + (ConvertTo-D32PowerShellAuthorityJsonText -Value $Value[$key]))) }
        return '{' + ($parts -join ',') + '}'
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $parts = [System.Collections.Generic.List[string]]::new()
        foreach ($item in $Value) { $parts.Add((ConvertTo-D32PowerShellAuthorityJsonText -Value $item)) }
        return '[' + ($parts -join ',') + ']'
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $parts = [System.Collections.Generic.List[string]]::new()
        foreach ($property in $Value.PSObject.Properties) { $parts.Add(([System.Text.Json.JsonSerializer]::Serialize([string]$property.Name, [type][string], [System.Text.Json.JsonSerializerOptions]::new()) + ':' + (ConvertTo-D32PowerShellAuthorityJsonText -Value $property.Value))) }
        return '{' + ($parts -join ',') + '}'
    }
    throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: unsupported JSON candidate value type: $($Value.GetType().FullName)"
}

function Copy-D32PowerShellAuthorityJsonShape {
    param([Parameter(Mandatory = $true)][object]$Value)

    # SelfTest mutations must preserve the JSON wire types consumed by strict
    # readers. PSSerializer round-trips a one-item array as ArrayList, which is
    # not the JSON array type required by the module-admission validator. Keep
    # this clone module-free: ConvertFrom-Json would autoload Utility here.
    # Its decoder intentionally returns ordered dictionaries; keep it separate
    # from the canonical authority decoder below, whose PSCustomObject shape is
    # consumed by strict runtime/bootstrap validators.
    $json = ConvertTo-D32PowerShellAuthorityJsonText -Value $Value
    $jsonDocument = [System.Text.Json.JsonDocument]::Parse($json)
    try { $copy = ConvertFrom-D32PowerShellAuthorityJsonShapeElement -Element $jsonDocument.RootElement }
    finally { $jsonDocument.Dispose() }
    if ($null -eq $copy) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: JSON-shape copy unexpectedly decoded as null' }
    return ,$copy
}

function ConvertFrom-D32PowerShellAuthorityJsonShapeElement {
    param([Parameter(Mandatory = $true)][System.Text.Json.JsonElement]$Element)

    switch ($Element.ValueKind) {
        ([System.Text.Json.JsonValueKind]::Object) {
            $record = [ordered]@{}
            foreach ($property in $Element.EnumerateObject()) {
                if ($record.Contains($property.Name)) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: duplicate JSON property in SelfTest shape copy' }
                $record[$property.Name] = ConvertFrom-D32PowerShellAuthorityJsonShapeElement -Element $property.Value
            }
            return ,$record
        }
        ([System.Text.Json.JsonValueKind]::Array) {
            $items = [System.Collections.Generic.List[object]]::new()
            foreach ($item in $Element.EnumerateArray()) { $items.Add((ConvertFrom-D32PowerShellAuthorityJsonShapeElement -Element $item)) }
            return ,$items.ToArray()
        }
        ([System.Text.Json.JsonValueKind]::String) { return $Element.GetString() }
        ([System.Text.Json.JsonValueKind]::Number) {
            [Int64]$signed = 0
            if ($Element.TryGetInt64([ref]$signed)) { return $signed }
            [UInt64]$unsigned = 0
            if ($Element.TryGetUInt64([ref]$unsigned)) { return $unsigned }
            throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: nonintegral JSON numbers are unsupported in SelfTest shape copies'
        }
        ([System.Text.Json.JsonValueKind]::True) { return $true }
        ([System.Text.Json.JsonValueKind]::False) { return $false }
        ([System.Text.Json.JsonValueKind]::Null) { return $null }
        default { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: unsupported JSON token in SelfTest shape copy' }
    }
}

function Get-D32PowerShellAuthorityProcessStartup {
    param([Parameter(Mandatory = $true)][string]$EntryScriptPath, [AllowNull()][string[]]$ArgumentVector)
    $arguments = if ($null -eq $ArgumentVector) { [Environment]::GetCommandLineArgs() } else { [string[]]$ArgumentVector }
    $fileIndex = -1
    for ($index = 1; $index -lt $arguments.Length; $index++) {
        if ([StringComparer]::OrdinalIgnoreCase.Equals([string]$arguments[$index], '-File')) { $fileIndex = $index; break }
    }
    if ($fileIndex -lt 0 -or $fileIndex + 1 -ge $arguments.Length) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: direct -File startup is required; command, encoded, wrapper, and ambiguous modes are rejected' }
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $noProfile = $false
    for ($index = 1; $index -lt $fileIndex; $index++) {
        $option = [string]$arguments[$index]
        if ($option -cnotin @('-NoLogo', '-NoProfile', '-NonInteractive') -or -not $seen.Add($option)) {
            throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: startup switch is unknown, duplicated, or ambiguous'
        }
        if ([StringComparer]::OrdinalIgnoreCase.Equals($option, '-NoProfile')) { $noProfile = $true }
    }
    if (-not $noProfile) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: exact direct runner startup requires -NoProfile before -File' }
    $operand = [string]$arguments[$fileIndex + 1]
    if (-not [IO.Path]::IsPathRooted($operand)) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: -File operand must be absolute' }
    $operand = [IO.Path]::GetFullPath($operand)
    $expected = [IO.Path]::GetFullPath($EntryScriptPath)
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($operand, $expected)) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: actual -File operand does not name this runner' }
    $switches = @()
    if ($fileIndex -gt 1) { $switches = [string[]]$arguments[1..($fileIndex - 1)] }
    return [PSCustomObject]@{ FileOperand = $operand; Switches = [string[]]$switches; ProcessArguments = [string[]]$arguments }
}

function Get-D32PowerShellAuthorityResolverSnapshotFromAdmission {
    param([Parameter(Mandatory = $true)][object]$Admission)
    $resolver = $Admission.resolver_admission
    $nativeComponents = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($nativeRecord in @($Admission.import_verification.native_modules)) {
        if (-not $nativeComponents.TryAdd([string]$nativeRecord.path, [string]$nativeRecord.component_type)) {
            throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: admitted resolver context repeats an actual native origin'
        }
    }
    $digests = Get-D32PowerShellAuthorityResolverDigestSet -ModuleSearchPath ([string]$resolver.module_search_path) `
        -OsSecurityInventorySha256 ([string]$resolver.os_security_inventory_sha256) -TrustedPlatformPaths ([string[]]$resolver.trusted_platform_paths) `
        -DepsPaths ([string[]]$resolver.deps_paths) -NativeDirectories ([string[]]$resolver.native_directories) `
        -NativeModulePaths ([string[]]$resolver.native_module_paths) -ActiveEnvironment ([object[]]$resolver.active_environment) `
        -NativePolicy ([string]$resolver.native_policy) -NativeFileComponents $nativeComponents
    if ($digests.ResolverSha256 -cne [string]$resolver.resolver_sha256) {
        throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: admitted resolver digest does not match its typed actual-origin records'
    }
    return [PSCustomObject]@{
        Blockers = [string[]]@(); TrustedPlatformPaths = [string[]]$resolver.trusted_platform_paths
        LoadedManagedAssemblyPaths = [string[]]$resolver.loaded_managed_assembly_paths; DepsPaths = [string[]]$resolver.deps_paths
        NativeDirectories = [string[]]$resolver.native_directories; NativeModulePaths = [string[]]$resolver.native_module_paths
        ActiveEnvironment = [object[]]$resolver.active_environment; NativePolicy = [string]$resolver.native_policy
        ModuleSearchPath = [string]$resolver.module_search_path; ResolverSha256 = [string]$digests.ResolverSha256
        PolicySha256 = [string]$digests.PolicySha256; NativeModulePathsSha256 = [string]$digests.NativeModulePathsSha256
        OsSecurityInventorySha256 = [string]$resolver.os_security_inventory_sha256; NativeFileComponents = $nativeComponents
    }
}

function Get-D32PowerShellAuthorityNativeOriginEvidence {
    param(
        [Parameter(Mandatory = $true)][object]$ResolverSnapshot,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$RuntimeDistributionFiles,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$OsSecurityComponents,
        [Parameter(Mandatory = $true)][string]$PowerShellRoot
    )
    $runtimeByPath = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($file in $RuntimeDistributionFiles) { if (-not $runtimeByPath.TryAdd([string]$file.path, $file)) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: PowerShell distribution repeats a native content path' } }
    $osByPath = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($component in $OsSecurityComponents) {
        foreach ($file in @($component.native_files)) {
            if (-not $osByPath.TryAdd([string]$file.path, [PSCustomObject]@{ ComponentType = [string]$component.component_type; File = $file })) {
                throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: Windows/Defender authority repeats a native content path'
            }
        }
    }
    $evidence = [System.Collections.Generic.List[object]]::new()
    foreach ($path in $ResolverSnapshot.NativeModulePaths) {
        if (Test-D32PowerShellAuthorityPathWithin -Child ([string]$path) -Parent $PowerShellRoot) {
            if (-not $runtimeByPath.ContainsKey([string]$path)) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: observed PowerShell native origin is absent from the exact pinned distribution inventory' }
            $file = $runtimeByPath[[string]$path]
            $source = 'PSHOME_DISTRIBUTION'; $componentType = 'POWERSHELL_DISTRIBUTION'
        }
        else {
            if (-not $osByPath.ContainsKey([string]$path)) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: observed OS native origin is absent from the exact pinned component inventory' }
            $entry = $osByPath[[string]$path]; $file = $entry.File; $componentType = [string]$entry.ComponentType
            $source = if ($componentType -ceq 'MICROSOFT_WINDOWS_OS_INSTALLATION') { 'WINDOWS_OS_COMPONENT' } else { 'DEFENDER_PLATFORM_COMPONENT' }
        }
        $evidence.Add([ordered]@{
            path = [string]$path; source = $source; component_type = $componentType; bytes = [Int64]$file.bytes
            sha256 = [string]$file.sha256; volume_serial_hex = [string]$file.volume_serial_hex; file_id_hex = [string]$file.file_id_hex
            owner_sid = [string]$file.owner_sid; security_descriptor_sha256 = [string]$file.security_descriptor_sha256
        })
    }
    return ,$evidence.ToArray()
}

function Update-D32PowerShellAuthorityAdmissionResolverSnapshot {
    param(
        [Parameter(Mandatory = $true)][object]$Admission,
        [Parameter(Mandatory = $true)][object]$ResolverSnapshot,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$NativeEvidence
    )
    $Admission.module_closure.resolver_sha256 = [string]$ResolverSnapshot.ResolverSha256
    $resolver = $Admission.resolver_admission
    $resolver.resolver_sha256 = [string]$ResolverSnapshot.ResolverSha256
    $resolver.os_security_inventory_sha256 = [string]$ResolverSnapshot.OsSecurityInventorySha256
    $resolver.native_policy = [string]$ResolverSnapshot.NativePolicy
    $resolver.module_search_path = [string]$ResolverSnapshot.ModuleSearchPath
    $resolver.trusted_platform_paths = @($ResolverSnapshot.TrustedPlatformPaths)
    $resolver.loaded_managed_assembly_paths = @($ResolverSnapshot.LoadedManagedAssemblyPaths)
    $resolver.deps_paths = @($ResolverSnapshot.DepsPaths)
    $resolver.native_directories = @($ResolverSnapshot.NativeDirectories)
    $resolver.native_module_paths = @($ResolverSnapshot.NativeModulePaths)
    $resolver.active_environment = @($ResolverSnapshot.ActiveEnvironment)
    $Admission.import_verification.native_modules = @($NativeEvidence)
}

function Assert-D32PowerShellModuleAdmissionCurrent {
    param([Parameter(Mandatory = $true)][object]$State)
    if ($PSModuleAutoLoadingPreference -cne 'None' -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$PSHOME), [string]$State.PowerShellRoot) -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$env:PSModulePath), [string]$State.ModuleRoot)) {
        throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: module autoload or module search policy changed after admission'
    }
    $startup = Get-D32PowerShellAuthorityProcessStartup -EntryScriptPath ([string]$State.Startup.FileOperand)
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($startup.FileOperand, [string]$State.Startup.FileOperand) -or
        $startup.Switches.Count -ne $State.Startup.Switches.Count) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: runner startup binding changed' }
    for ($index = 0; $index -lt $startup.Switches.Count; $index++) {
        if (-not [StringComparer]::OrdinalIgnoreCase.Equals([string]$startup.Switches[$index], [string]$State.Startup.Switches[$index])) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: runner startup switch binding changed' }
    }
    $currentToken = Get-D32PowerShellAuthorityCurrentToken
    if (-not (Test-D32PowerShellAuthorityTokenRecord -Token $State.Admission.runner_process.token_state) -or
        $currentToken.is_elevated -ne $State.Admission.runner_process.token_state.is_elevated -or
        [Int64]$currentToken.integrity_rid -ne [Int64]$State.Admission.runner_process.token_state.integrity_rid -or
        $currentToken.is_system -ne $State.Admission.runner_process.token_state.is_system -or
        $currentToken.thread_impersonating -ne $State.Admission.runner_process.token_state.thread_impersonating) {
        throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: process token trust state changed at admission reuse boundary'
    }
    foreach ($file in $State.OpenFiles) {
        $stream = $file.Stream
        if ($null -eq $stream -or $stream.SafeFileHandle.IsClosed -or $stream.SafeFileHandle.IsInvalid) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: a held admitted file handle was released' }
        $before = Get-D32PowerShellAuthorityHandleIdentity -Handle $stream.SafeFileHandle
        if (-not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$stream.Name), [string]$file.Record.path) -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals((Get-D32PowerShellAuthorityFinalHandlePath -Handle $stream.SafeFileHandle), [string]$file.Record.path) -or
            $before.Bytes -ne [Int64]$file.Record.bytes -or $before.VolumeSerialHex -cne [string]$file.Record.volume_serial_hex -or $before.FileIdHex -cne [string]$file.Record.file_id_hex) {
            throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: held file identity drifted: $($file.Record.path)"
        }
        $stream.Position = 0
        $sha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant()
        if ($sha -cne [string]$file.Record.sha256 -or $stream.Length -ne [Int64]$file.Record.bytes) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: held file content drifted: $($file.Record.path)" }
        if ((Test-D32PowerShellAuthorityPathWithin -Child ([string]$file.Record.path) -Parent ([string]$State.PowerShellRoot)) -or
            $State.OsProtectedFilePaths.Contains([string]($file.Record.path))) {
            $security = Get-D32PowerShellAuthorityObjectSecurity -Path ([string]$file.Record.path) -IsDirectory:$false -Handle $stream.SafeFileHandle -Stream $stream
            if (-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $security -IsDirectory:$false) -or
                $security.OwnerSid -cne [string]$file.Security.OwnerSid -or $security.AclSha256 -cne [string]$file.Security.AclSha256) {
                throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: protected PowerShell/OS component file owner/ACL changed: $($file.Record.path)"
            }
        }
    }
    foreach ($directory in $State.DirectoryFences.Values) {
        if ($directory.Handle.IsClosed -or $directory.Handle.IsInvalid) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: an admitted ancestor directory fence was released' }
        $identity = Get-D32PowerShellAuthorityHandleIdentity -Handle $directory.Handle
        if (($identity.Attributes -band [int][IO.FileAttributes]::Directory) -eq 0 -or ($identity.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals((Get-D32PowerShellAuthorityFinalHandlePath -Handle $directory.Handle), [string]$directory.Path) -or
            $identity.VolumeSerialHex -cne [string]$directory.VolumeSerialHex -or $identity.FileIdHex -cne [string]$directory.FileIdHex) {
            throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: ancestor directory identity drifted: $($directory.Path)"
        }
        $isRuntimeDirectory = Test-D32PowerShellAuthorityPathWithin -Child ([string]$directory.Path) -Parent ([string]$State.PowerShellRoot)
        $isRuntimeAncestor = -not $isRuntimeDirectory -and (Test-D32PowerShellAuthorityPathWithin -Child ([string]$State.PowerShellRoot) -Parent ([string]$directory.Path))
        $isOsDirectory = $State.OsSecurityDirectoryPaths.Contains([string]$directory.Path)
        $isOsAncestor = $State.OsSecurityAncestorPaths.Contains([string]$directory.Path)
        $isDefenderAncestor = $isOsAncestor -and [StringComparer]::OrdinalIgnoreCase.Equals([string]$directory.Path, 'C:\ProgramData')
        $isProtectedNamespace = $isRuntimeDirectory -or $isRuntimeAncestor -or $isOsDirectory -or $isOsAncestor
        if ($isProtectedNamespace) {
            $security = Get-D32PowerShellAuthorityObjectSecurity -Path ([string]$directory.Path) -IsDirectory:$true -Handle $directory.Handle
            $isProtectedAncestor = $isRuntimeAncestor -or $isOsAncestor
            if (-not (Test-D32PowerShellAuthorityProtectedSecurity -Security $security -IsDirectory:$true -IsProtectedAncestor:$isProtectedAncestor -IsProgramDataAncestor:$isDefenderAncestor) -or
                $security.OwnerSid -cne [string]$directory.OwnerSid -or $security.AclSha256 -cne [string]$directory.AclSha256) {
                throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: protected PowerShell/OS component directory owner/ACL changed: $($directory.Path)"
            }
        }
    }
    Assert-D32PowerShellAuthorityRuntimeEntriesCurrent -Snapshot $State.RuntimeDistribution
    if ($State.OsSecurityComponents.Count -ne 2 -or
        [string]$State.OsSecurityComponents[0].component_type -cne 'MICROSOFT_WINDOWS_OS_INSTALLATION' -or
        [string]$State.OsSecurityComponents[1].component_type -cne 'MICROSOFT_WINDOWS_DEFENDER_PLATFORM') {
        throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: admitted OS component roles are missing or reordered at reuse boundary'
    }
    $windowsComponent = $State.OsSecurityComponents[0]
    $defenderComponent = $State.OsSecurityComponents[1]
    $windowsRoot = Get-D32PowerShellAuthorityWindowsRootPath
    $systemRoot = [IO.Path]::GetFullPath([string]$env:SystemRoot)
    $osVersion = [Environment]::OSVersion.VersionString
    $windowsSource = $windowsComponent.source_proof
    $defenderRoot = [IO.Path]::GetFullPath([string]$defenderComponent.root_path)
    $expectedWindowsRoot = [IO.Path]::GetFullPath([string]$windowsComponent.root_path)
    $expectedSystemRoot = [IO.Path]::GetFullPath([string]$windowsSource.environment_system_root)
    $defenderParent = [IO.Path]::GetDirectoryName($defenderRoot)
    $componentDigest = Get-D32PowerShellAuthorityOsSecurityInventoryDigest -Components $State.OsSecurityComponents
    $verificationFiles = [System.Collections.Generic.List[object]]::new()
    $currentDefender = $null
    $defenderDistributionDiff = $null
    try {
        $currentDefender = Get-D32PowerShellAuthorityDefenderPlatformSnapshot -RootPath $defenderRoot `
            -DirectoryFences $State.DirectoryFences -OpenFiles $verificationFiles
        $defenderDistributionDiff = Get-D32PowerShellAuthorityRuntimeDistributionDiff `
            -Expected $defenderComponent.distribution -Actual $currentDefender `
            -PowerShellRoot $State.PowerShellRoot -WindowsRoot $expectedWindowsRoot -DefenderRoot $defenderRoot
    }
    finally {
        foreach ($file in $verificationFiles) {
            if ($null -ne $file.Stream -and -not $file.Stream.SafeFileHandle.IsClosed) { $file.Stream.Dispose() }
        }
    }
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($windowsRoot, $expectedWindowsRoot) -or
        -not [StringComparer]::Ordinal.Equals($systemRoot, $expectedSystemRoot) -or
        $osVersion -cne [string]$windowsSource.os_version -or
        [string]$windowsSource.api_path -cne [string]$windowsComponent.root_path -or
        [string]$windowsComponent.version -cne $osVersion -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals($defenderParent, 'C:\ProgramData\Microsoft\Windows Defender\Platform') -or
        [IO.Path]::GetFileName($defenderRoot) -cne [string]$defenderComponent.version -or
        $currentDefender.inventory_sha256 -cne [string]$defenderComponent.distribution.inventory_sha256 -or
        $defenderDistributionDiff.Added.Count -gt 0 -or $defenderDistributionDiff.Removed.Count -gt 0 -or $defenderDistributionDiff.Changed.Count -gt 0 -or
        $componentDigest -cne [string]$State.OsSecurityInventorySha256 -or
        $componentDigest -cne [string]$State.Admission.resolver_admission.os_security_inventory_sha256) {
        $diagnostic = [ordered]@{
            record_type = 'D32_POWERSHELL_OS_COMPONENT_REUSE_DIAGNOSTIC_V2'
            role_order = @([string]$windowsComponent.component_type, [string]$defenderComponent.component_type)
            windows = [ordered]@{
                pinned_root = $expectedWindowsRoot; actual_root = $windowsRoot
                pinned_environment_root = $expectedSystemRoot; actual_environment_root = $systemRoot
                pinned_version = [string]$windowsComponent.version; actual_version = $osVersion
                pinned_api_path = [string]$windowsSource.api_path
            }
            defender = [ordered]@{
                pinned_root = $defenderRoot; pinned_version = [string]$defenderComponent.version
                pinned_inventory_sha256 = [string]$defenderComponent.distribution.inventory_sha256
                actual_inventory_sha256 = [string]$currentDefender.inventory_sha256
                path_differences = [ordered]@{
                    added = @($defenderDistributionDiff.Added); removed = @($defenderDistributionDiff.Removed); changed = @($defenderDistributionDiff.Changed)
                }
            }
            component_inventory = [ordered]@{
                state_sha256 = [string]$State.OsSecurityInventorySha256
                admission_sha256 = [string]$State.Admission.resolver_admission.os_security_inventory_sha256
                recomputed_from_admitted_components_sha256 = [string]$componentDigest
            }
        }
        throw ('POWERSHELL_MODULE_AUTHORITY_BLOCKED: admitted Windows/Defender source binding changed at reuse boundary; diagnostic=' + (ConvertTo-D32PowerShellAuthorityJsonText -Value $diagnostic))
    }
    $process = [Diagnostics.Process]::GetCurrentProcess()
    try {
        if ($process.Id -ne [Int32]$State.Admission.runner_process.process_id -or
            [Int64]$process.StartTime.ToUniversalTime().Ticks -ne [Int64]$State.Admission.runner_process.start_time_utc_ticks -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$process.MainModule.FileName), [string]$State.Admission.powershell_host.path)) {
            throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: current process identity differs from the admitted runner process'
        }
    }
    finally { $process.Dispose() }
    $priorResolver = Get-D32PowerShellAuthorityResolverSnapshotFromAdmission -Admission $State.Admission
    # The component inventory is the caller-pinned source/content authority. The
    # Defender package inventory was re-enumerated above, but native/managed
    # process origins remain a separate runtime observation checked below
    # against exact admitted file references. Rebuilding component authority
    # from the process's current module list would conflate those two records.
    $currentResolver = Get-D32PowerShellAuthorityResolverSnapshot -OsSecurityComponents $State.OsSecurityComponents `
        -OsSecurityInventorySha256 ([string]$State.OsSecurityInventorySha256) -ConfigureNativeSearch
    $transitionNativeFiles = [System.Collections.Generic.List[object]]::new()
    foreach ($file in $State.RuntimeDistribution.files) { $transitionNativeFiles.Add($file) }
    $transitionManagedFiles = [System.Collections.Generic.List[object]]::new()
    foreach ($file in $State.RuntimeDistribution.files) { $transitionManagedFiles.Add($file) }
    foreach ($component in $State.OsSecurityComponents) {
        foreach ($file in @($component.native_files)) { $transitionNativeFiles.Add($file) }
        foreach ($file in @($component.distribution.files)) { $transitionManagedFiles.Add($file) }
    }
    $resolverTransition = Test-D32PowerShellAuthorityResolverSnapshotTransition -Before $priorResolver -After $currentResolver `
        -PinnedNativeFiles $transitionNativeFiles.ToArray() -PinnedManagedFiles $transitionManagedFiles.ToArray() `
        -PowerShellRoot ([string]$State.PowerShellRoot) -WindowsRoot $expectedWindowsRoot -DefenderRoot $defenderRoot
    if (-not $resolverTransition.Passed) {
        $diagnosticText = ConvertTo-D32PowerShellAuthorityJsonText -Value $resolverTransition.Diagnostic
        throw ('POWERSHELL_MODULE_AUTHORITY_BLOCKED: current resolver admission transition denied; diagnostic=' + $diagnosticText)
    }
    $nativeEvidence = Get-D32PowerShellAuthorityNativeOriginEvidence -ResolverSnapshot $currentResolver -RuntimeDistributionFiles $State.RuntimeDistribution.files `
        -OsSecurityComponents $State.OsSecurityComponents -PowerShellRoot ([string]$State.PowerShellRoot)
    Update-D32PowerShellAuthorityAdmissionResolverSnapshot -Admission $State.Admission -ResolverSnapshot $currentResolver -NativeEvidence $nativeEvidence
    if ($State.ImportAttempts -lt 3 -or $State.Admission.record_type -cne 'D32_POWERSHELL_MODULE_ADMISSION_V2') { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: module admission did not complete the three fixed imports' }
    $moduleInfos = @(Microsoft.PowerShell.Core\Get-Module)
    foreach ($info in $moduleInfos) {
        if ([string]$info.Name -ceq 'Microsoft.PowerShell.Core') { continue }
        $expected = $State.ExpectedModuleManifestPaths[[string]$info.Name]
        if ($null -eq $expected -or [string]$info.Path -cnotin $expected) {
            throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: unexpected loaded module or module path: $($info.Name)"
        }
    }
    $commandOrigins = [System.Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($moduleName in $State.ImportOrder) {
        $match = [System.Collections.Generic.List[object]]::new()
        foreach ($candidate in $moduleInfos) { if ([string]$candidate.Name -ceq $moduleName) { $match.Add($candidate) } }
        if ($match.Count -ne 1 -or [string]$match[0].Path -cnotin $State.ExpectedModuleManifestPaths[$moduleName]) {
            throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: fixed module is not uniquely loaded from its pinned manifest: $moduleName"
        }
        foreach ($command in $match[0].ExportedCommands.Values) {
            if ($null -eq $command.Module -or [string]$command.Module.Name -cne $moduleName -or [string]$command.Module.Path -cnotin $State.ExpectedModuleManifestPaths[$moduleName]) {
                throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: exported command origin differs from its pinned module: $($command.Name)"
            }
            $key = $moduleName + '|' + [string]$command.Name
            $effectiveCommands = @(Microsoft.PowerShell.Core\Get-Command -Name ([string]$command.Name) -All -ErrorAction Stop)
            if ($effectiveCommands.Count -eq 0) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: exported command is not discoverable after fixed imports: $($command.Name)" }
            $effective = $effectiveCommands[0]
            foreach ($candidateCommand in $effectiveCommands) {
                if ($null -eq $candidateCommand.Module -or [string]$candidateCommand.Module.Name -cnotin $State.ImportOrder -or
                    [string]$candidateCommand.Module.Path -cnotin $State.ExpectedModuleManifestPaths[[string]$candidateCommand.Module.Name]) {
                    throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: effective command resolution found an unadmitted shadow or origin: $($command.Name)"
                }
            }
            $commandOrigins[$key] = [ordered]@{
                module_name = $moduleName; command_name = [string]$command.Name; module_path = [string]$command.Module.Path
                effective_module_name = [string]$effective.Module.Name; effective_module_path = [string]$effective.Module.Path
            }
        }
    }
    $State.Admission.import_verification.commands = @($commandOrigins.Values)
    if (-not (Test-D32PowerShellModuleAdmissionRecord -Document $State.Admission -CandidateSha ([string]$State.Admission.candidate_sha) -Repository ([string]$State.Admission.source_repo))) {
        throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: stale, forged, or malformed shared admission context; validator_context=$script:D32PowerShellModuleAdmissionValidationContext"
    }
}

function Initialize-D32PowerShellModuleAuthority {
    [CmdletBinding()]
    param(
        [AllowNull()][string]$CallerProfilePath,
        [AllowNull()][string]$CallerExpectedProfileSha256,
        [AllowNull()][string]$CallerModuleAuthorityPath,
        [AllowNull()][string]$CallerExpectedModuleAuthoritySha256,
        [AllowNull()][string]$CallerCandidateSha,
        [AllowNull()][string]$CallerRepository,
        [AllowNull()][string]$CallerGitPath,
        [AllowNull()][string]$CallerGitSha256,
        [AllowNull()][string]$EntryScriptPath,
        [switch]$LocalSelfTestOnly
    )
    $priorState = $global:D32PowerShellModuleAuthorityState
    $global:D32PowerShellModuleImportAttempts = if ($null -eq $priorState) { 0 } else { [int]$priorState.ImportAttempts }
    if ($null -ne $priorState) {
        try {
            if ([String]::IsNullOrWhiteSpace($CallerModuleAuthorityPath) -or [String]::IsNullOrWhiteSpace($CallerExpectedModuleAuthoritySha256) -or
                [String]::IsNullOrWhiteSpace($CallerProfilePath) -or [String]::IsNullOrWhiteSpace($CallerExpectedProfileSha256) -or
                [String]::IsNullOrWhiteSpace($CallerCandidateSha) -or [String]::IsNullOrWhiteSpace($CallerRepository) -or
                [String]::IsNullOrWhiteSpace($CallerGitPath) -or [String]::IsNullOrWhiteSpace($CallerGitSha256) -or [String]::IsNullOrWhiteSpace($EntryScriptPath)) {
                throw 'all caller-owned authority, Profile, Git, candidate, repository, and library-entry pins are required for reuse'
            }
            foreach ($inputPath in @($CallerModuleAuthorityPath, $CallerProfilePath, $CallerGitPath, $CallerRepository, $EntryScriptPath)) {
                if (-not [IO.Path]::IsPathRooted([string]$inputPath) -or [IO.Path]::GetFullPath([string]$inputPath) -cne [string]$inputPath -or
                    -not (Test-D32PowerShellAuthorityPathNoReparse -Path ([string]$inputPath))) { throw 'a library-reuse caller path is not canonical and non-reparse' }
            }
            if ([IO.Path]::GetFullPath($CallerModuleAuthorityPath) -cne [string]$priorState.AuthorityReference.path -or $CallerExpectedModuleAuthoritySha256 -cne [string]$priorState.AuthorityReference.sha256 -or
                [IO.Path]::GetFullPath($CallerProfilePath) -cne [string]$priorState.ProfileReference.path -or $CallerExpectedProfileSha256 -cne [string]$priorState.ProfileReference.sha256 -or
                [IO.Path]::GetFullPath($CallerGitPath) -cne [string]$priorState.Admission.git_image.path -or $CallerGitSha256 -cne [string]$priorState.Admission.git_image.sha256 -or
                $CallerCandidateSha -cne [string]$priorState.Admission.candidate_sha -or
                -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath($CallerRepository), [string]$priorState.RepositoryRoot) -or
                -not (Test-D32PowerShellAuthorityPathWithin -Child $EntryScriptPath -Parent ([string]$priorState.RepositoryRoot))) {
                throw 'library-reuse authority pins, candidate, repository, or entry binding changed'
            }
            if (-not (Test-D32PowerShellModuleAdmissionRecord -Document $priorState.Admission -CandidateSha $CallerCandidateSha -Repository $CallerRepository -ExpectedContext $priorState.Admission)) {
                throw 'library-reuse admission record is not a complete self-validating exact V2 record'
            }
            Assert-D32PowerShellModuleAdmissionCurrent -State $priorState
        }
        catch { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: forged, stale, or incomplete library-reuse context: $($_.Exception.Message)" }
        return $priorState.Admission
    }

    $global:PSModuleAutoLoadingPreference = 'None'
    $global:D32PowerShellModuleImportAttempts = 0
    if ([String]::IsNullOrWhiteSpace($CallerModuleAuthorityPath) -or [String]::IsNullOrWhiteSpace($CallerExpectedModuleAuthoritySha256) -or
        [String]::IsNullOrWhiteSpace($CallerProfilePath) -or [String]::IsNullOrWhiteSpace($CallerExpectedProfileSha256) -or
        [String]::IsNullOrWhiteSpace($CallerCandidateSha) -or [String]::IsNullOrWhiteSpace($CallerRepository) -or
        [String]::IsNullOrWhiteSpace($CallerGitPath) -or [String]::IsNullOrWhiteSpace($CallerGitSha256)) {
        throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: no-pin startup, SelfTest, and LibraryOnly modes are limited to module-free negative/bootstrap work'
    }
    if ($CallerCandidateSha -cnotmatch '^[0-9a-f]{40}$' -or $CallerExpectedProfileSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $CallerExpectedModuleAuthoritySha256 -cnotmatch '^[0-9a-f]{64}$' -or $CallerGitSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: candidate and all external content pins must be exact lowercase digests'
    }
    if ([String]::IsNullOrWhiteSpace($EntryScriptPath)) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: exact runner path is required' }
    $startup = Get-D32PowerShellAuthorityProcessStartup -EntryScriptPath $EntryScriptPath
    $repo = [IO.Path]::GetFullPath($CallerRepository)
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($repo, $CallerRepository) -or -not (Test-D32PowerShellAuthorityPathNoReparse -Path $repo)) {
        throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: repository binding must be canonical and non-reparse'
    }
    $entryScript = [IO.Path]::GetFullPath($EntryScriptPath)
    if (-not (Test-D32PowerShellAuthorityPathWithin -Child $entryScript -Parent $repo) -or [StringComparer]::OrdinalIgnoreCase.Equals($entryScript, $repo) -or
        -not (Test-D32PowerShellAuthorityPathNoReparse -Path $entryScript)) {
        throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: runner entrypoint is outside the canonical non-reparse candidate repository'
    }
    $powerShellRoot = [IO.Path]::GetFullPath([string]$PSHOME)
    if ([string]$PSVersionTable.PSEdition -cne 'Core' -or [Version]$PSVersionTable.PSVersion -lt [Version]'7.5' -or
        -not (Test-D32PowerShellAuthorityPathNoReparse -Path $powerShellRoot)) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: unsupported PowerShell Core host or PSHOME' }
    $moduleRoot = [IO.Path]::GetFullPath([IO.Path]::Combine($powerShellRoot, 'Modules'))
    $global:PSModuleAutoLoadingPreference = 'None'
    $env:PSModulePath = $moduleRoot

    $directoryFences = [System.Collections.Specialized.OrderedDictionary]::new([StringComparer]::OrdinalIgnoreCase)
    $script:D32PowerShellAdmissionDirectoryFences = $directoryFences
    $openFiles = [System.Collections.Generic.List[object]]::new()
    $moduleRecords = [System.Collections.Generic.List[object]]::new()
    $importAttempts = 0
    try {
        foreach ($inputPath in @($CallerModuleAuthorityPath, $CallerProfilePath, $CallerGitPath)) {
            if (-not [IO.Path]::IsPathRooted([string]$inputPath) -or [IO.Path]::GetFullPath([string]$inputPath) -cne [string]$inputPath -or
                -not (Test-D32PowerShellAuthorityPathNoReparse -Path ([string]$inputPath))) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: authority/Profile/Git caller paths must be canonical absolute regular paths' }
        }
        foreach ($inputPath in @($CallerModuleAuthorityPath, $CallerProfilePath, $CallerGitPath)) {
            if ((Test-D32PowerShellAuthorityPathWithin -Child ([string]$inputPath) -Parent $repo) -or
                (Test-D32PowerShellAuthorityPathWithin -Child $repo -Parent ([string]$inputPath))) {
                throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: external authority, Profile V2, and Git image must be outside and non-overlapping with the candidate repository'
            }
        }
        $entrySnapshot = Open-D32PowerShellAuthorityFile -Path $entryScript -DirectoryFences $directoryFences
        $openFiles.Add($entrySnapshot)
        $authorityFile = Open-D32PowerShellAuthorityFile -Path ([IO.Path]::GetFullPath($CallerModuleAuthorityPath)) -DirectoryFences $directoryFences
        $openFiles.Add($authorityFile)
        $profileFile = Open-D32PowerShellAuthorityFile -Path ([IO.Path]::GetFullPath($CallerProfilePath)) -DirectoryFences $directoryFences
        $openFiles.Add($profileFile)
        $gitFile = Open-D32PowerShellAuthorityFile -Path ([IO.Path]::GetFullPath($CallerGitPath)) -DirectoryFences $directoryFences
        $openFiles.Add($gitFile)
        if ($profileFile.Record.sha256 -cne $CallerExpectedProfileSha256 -or $gitFile.Record.sha256 -cne $CallerGitSha256 -or
            $authorityFile.Record.sha256 -cne $CallerExpectedModuleAuthoritySha256) {
            throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: external Profile, Git, or module-content caller pin mismatch'
        }
        $authorityText = [Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$authorityFile.Bytes)
        $authorityDocument = [System.Text.Json.JsonDocument]::Parse($authorityText)
        try {
            $authority = $authorityDocument.RootElement
            if (Test-D32PowerShellAuthorityJsonDuplicates -Element $authority) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: duplicate JSON keys in module authority' }
            Assert-D32PowerShellAuthorityExactJsonRecord -Element $authority -Fields @('schema_version','authority_type','status','gate_authority','candidate_sha','source_repo','profile','powershell_host','powershell_root','distribution','resolver_policy','modules') -Name 'module authority'
            if ($authority.GetProperty('schema_version').ValueKind -ne [System.Text.Json.JsonValueKind]::Number -or $authority.GetProperty('schema_version').GetInt32() -ne 2 -or
                (Get-D32PowerShellAuthorityJsonString $authority 'authority_type') -cne 'D32_POWERSHELL_MODULE_CONTENT_AUTHORITY_V2' -or
                (Get-D32PowerShellAuthorityJsonString $authority 'status') -cne 'CANDIDATE_FOR_COORDINATOR_PIN' -or
                (Get-D32PowerShellAuthorityJsonString $authority 'gate_authority') -cne 'NONE' -or
                (Get-D32PowerShellAuthorityJsonString $authority 'candidate_sha') -cne $CallerCandidateSha) {
                throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: module authority schema, candidate, or no-gate binding is invalid'
            }
            $authorityRepo = Get-D32PowerShellAuthorityJsonString $authority 'source_repo'
            if (-not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath($authorityRepo), $repo) -or $authorityRepo -cne [IO.Path]::GetFullPath($authorityRepo)) {
                throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: module authority repository path is not the exact canonical caller repository'
            }
            Assert-D32PowerShellAuthorityExactJsonRecord -Element $authority.GetProperty('profile') -Fields @('path','bytes','sha256','volume_serial_hex','file_id_hex') -Name 'module authority Profile reference'
            Assert-D32PowerShellAuthorityExactJsonRecord -Element $authority.GetProperty('powershell_host') -Fields @('path','bytes','sha256','volume_serial_hex','file_id_hex') -Name 'module authority PowerShell host'
            Assert-D32PowerShellAuthorityExactJsonRecord -Element $authority.GetProperty('powershell_root') -Fields @('path','volume_serial_hex','file_id_hex') -Name 'module authority PSHOME identity'
            Assert-D32PowerShellAuthorityFileRecord -Element $authority.GetProperty('profile') -Actual $profileFile -Name 'module authority Profile reference'
            $profileData = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$profileFile.Bytes))
            try {
                if (Test-D32PowerShellAuthorityJsonDuplicates -Element $profileData.RootElement) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: duplicate keys in caller Profile V2' }
                $profileElement = $profileData.RootElement
                Assert-D32PowerShellAuthorityExactJsonRecord -Element $profileElement -Fields @('schema_version','profile_type','target_triple','system_root','powershell_root','powershell','rust_toolchain_root','toolchain','rust_toolchain_bin_images','native_roots','native','windows_child_images','fetch_manifests','fetch_git','env_policy','cargo_policy') -Name 'caller Profile V2'
                if ($profileElement.GetProperty('schema_version').ValueKind -ne [System.Text.Json.JsonValueKind]::Number -or $profileElement.GetProperty('schema_version').GetInt32() -ne 2 -or
                    $profileElement.GetProperty('profile_type').ValueKind -ne [System.Text.Json.JsonValueKind]::String -or $profileElement.GetProperty('profile_type').GetString() -cne 'D32_BUILD_TOOLCHAIN_PROFILE_V2' -or
                    $profileElement.GetProperty('target_triple').ValueKind -ne [System.Text.Json.JsonValueKind]::String -or $profileElement.GetProperty('target_triple').GetString() -cne 'x86_64-pc-windows-msvc' -or
                    $profileElement.GetProperty('env_policy').ValueKind -ne [System.Text.Json.JsonValueKind]::String -or $profileElement.GetProperty('env_policy').GetString() -cne 'D32_BUILD_ENV_V1' -or
                    $profileElement.GetProperty('cargo_policy').ValueKind -ne [System.Text.Json.JsonValueKind]::String -or $profileElement.GetProperty('cargo_policy').GetString() -cne 'FRESH_HOME_LOCKED_FETCH_OFFLINE_AFTER') {
                    throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: caller Profile V2 exact type/version/policy is invalid'
                }
                $profileRootValue = $profileElement.GetProperty('powershell_root')
                if ($profileRootValue.ValueKind -ne [System.Text.Json.JsonValueKind]::String) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: Profile V2 powershell_root must be a string' }
                $profileRoot = [IO.Path]::GetFullPath($profileRootValue.GetString())
                if ($profileRootValue.GetString() -cne $profileRoot) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: Profile V2 powershell_root is not canonical' }
                $hostEntry = $profileElement.GetProperty('powershell')
                Assert-D32PowerShellAuthorityExactJsonRecord -Element $hostEntry -Fields @('name','path','sha256','bytes','volume_serial_hex','file_id_hex','reason') -Name 'Profile V2 PowerShell host identity'
                if ($hostEntry.GetProperty('name').ValueKind -ne [System.Text.Json.JsonValueKind]::String -or $hostEntry.GetProperty('name').GetString() -cne 'pwsh.exe' -or
                    $hostEntry.GetProperty('path').ValueKind -ne [System.Text.Json.JsonValueKind]::String -or $hostEntry.GetProperty('sha256').ValueKind -ne [System.Text.Json.JsonValueKind]::String -or
                    $hostEntry.GetProperty('bytes').ValueKind -ne [System.Text.Json.JsonValueKind]::Number -or $hostEntry.GetProperty('volume_serial_hex').ValueKind -ne [System.Text.Json.JsonValueKind]::String -or
                    $hostEntry.GetProperty('file_id_hex').ValueKind -ne [System.Text.Json.JsonValueKind]::String -or $hostEntry.GetProperty('reason').ValueKind -ne [System.Text.Json.JsonValueKind]::String) {
                    throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: Profile V2 PowerShell host identity types are invalid'
                }
                $hostPathValue = $hostEntry.GetProperty('path').GetString()
                $hostPath = [IO.Path]::GetFullPath($hostPathValue)
                if ($hostPathValue -cne $hostPath) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: Profile V2 PowerShell host path is not canonical' }
                $hostSha = $hostEntry.GetProperty('sha256').GetString()
                $hostBytes = $hostEntry.GetProperty('bytes').GetInt64()
                $hostVolume = $hostEntry.GetProperty('volume_serial_hex').GetString()
                $hostFileId = $hostEntry.GetProperty('file_id_hex').GetString()
            }
            finally { $profileData.Dispose() }
            if (-not [StringComparer]::OrdinalIgnoreCase.Equals($profileRoot, $powerShellRoot) -or
                -not [StringComparer]::OrdinalIgnoreCase.Equals($hostPath, [IO.Path]::Combine($powerShellRoot, 'pwsh.exe'))) {
                throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: Profile V2 host/root does not bind this actual PowerShell process'
            }
            $hostFile = Open-D32PowerShellAuthorityFile -Path $hostPath -DirectoryFences $directoryFences
            $openFiles.Add($hostFile)
            Assert-D32PowerShellAuthorityFileRecord -Element $authority.GetProperty('powershell_host') -Actual $hostFile -Name 'module authority PowerShell host'
            if ($hostFile.Record.sha256 -cne $hostSha -or [Int64]$hostFile.Record.bytes -ne [Int64]$hostBytes -or
                $hostFile.Record.volume_serial_hex -cne $hostVolume -or $hostFile.Record.file_id_hex -cne $hostFileId) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: current PowerShell image differs from Profile V2 opened identity' }
            $process = [Diagnostics.Process]::GetCurrentProcess()
            try {
                if (-not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath([string]$process.MainModule.FileName), $hostPath)) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: process image path differs from Profile V2' }
                $processId = [int]$process.Id
                $processStartTicks = [Int64]$process.StartTime.ToUniversalTime().Ticks
            }
            finally { $process.Dispose() }
            $rootKey = $powerShellRoot.TrimEnd([char[]]@('\','/'))
            if ($rootKey.Length -eq 2 -and $rootKey[1] -eq ':') { $rootKey += [IO.Path]::DirectorySeparatorChar }
            $rootFence = $directoryFences[$rootKey]
            Assert-D32PowerShellAuthorityDirectoryRecord -Element $authority.GetProperty('powershell_root') -Actual $rootFence -Name 'module authority PSHOME identity'
            $resolverPolicy = $authority.GetProperty('resolver_policy')
            $osSecurity = Assert-D32PowerShellAuthorityResolverPolicyRecord -Element $resolverPolicy -PowerShellRoot $powerShellRoot -DirectoryFences $directoryFences -OpenFiles $openFiles
            $runtimeDistribution = Get-D32PowerShellAuthorityRuntimeDistributionSnapshot -PowerShellRoot $powerShellRoot -DirectoryFences $directoryFences -OpenFiles $openFiles
            Assert-D32PowerShellAuthorityRuntimeDistributionRecord -Element $authority.GetProperty('distribution') -Actual $runtimeDistribution

            $moduleElements = $authority.GetProperty('modules')
            if ($moduleElements.ValueKind -ne [System.Text.Json.JsonValueKind]::Array -or $moduleElements.GetArrayLength() -ne 3) { throw 'POWERSHELL_MODULE_AUTHORITY_BLOCKED: module authority must list exactly the three fixed module roles' }
            $roles = @(Get-D32PowerShellAuthorityFixedModuleRoles -PowerShellRoot $powerShellRoot)
            $allFilePaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            $allFileIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            for ($roleIndex = 0; $roleIndex -lt $roles.Count; $roleIndex++) {
                $role = $roles[$roleIndex]
                $moduleElement = $moduleElements[$roleIndex]
                Assert-D32PowerShellAuthorityExactJsonRecord -Element $moduleElement -Fields @('role','module_name','manifest_path','files','inventory_sha256') -Name "module entry $($role.Name)"
                if ((Get-D32PowerShellAuthorityJsonString $moduleElement 'role') -cne [string]$role.Role -or
                    (Get-D32PowerShellAuthorityJsonString $moduleElement 'module_name') -cne [string]$role.Name -or
                    (Get-D32PowerShellAuthorityJsonString $moduleElement 'manifest_path') -cne [IO.Path]::GetFullPath([string]$role.Manifest)) {
                    throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: module authority entry differs from the fixed role/path: $($role.Name)"
                }
                $expectedFiles = Get-D32PowerShellAuthorityExpectedModuleFiles -PowerShellRoot $powerShellRoot -Role $role
                $openFiles.Add($expectedFiles.Manifest)
                $fileElements = $moduleElement.GetProperty('files')
                if ($fileElements.ValueKind -ne [System.Text.Json.JsonValueKind]::Array -or $fileElements.GetArrayLength() -ne $expectedFiles.Paths.Count) {
                    throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: module content closure is incomplete or has unknown files: $($role.Name)"
                }
                $declaredByPath = [System.Collections.Generic.Dictionary[string,System.Text.Json.JsonElement]]::new([StringComparer]::OrdinalIgnoreCase)
                foreach ($fileElement in $fileElements.EnumerateArray()) {
                    Assert-D32PowerShellAuthorityExactJsonRecord -Element $fileElement -Fields @('path','bytes','sha256','volume_serial_hex','file_id_hex') -Name "module file $($role.Name)"
                    $declaredPath = Get-D32PowerShellAuthorityJsonString $fileElement 'path'
                    if (-not [IO.Path]::IsPathRooted($declaredPath) -or -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath($declaredPath), $declaredPath) -or
                        -not $declaredByPath.TryAdd($declaredPath, $fileElement)) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: duplicate, relative, or noncanonical path in module closure: $declaredPath" }
                }
                $actualFileRecords = [System.Collections.Generic.List[object]]::new()
                foreach ($path in $expectedFiles.Paths) {
                    $snapshot = if ([StringComparer]::OrdinalIgnoreCase.Equals($path, [string]$expectedFiles.Manifest.Record.path)) { $expectedFiles.Manifest } else { Open-D32PowerShellAuthorityFile -Path $path -DirectoryFences $directoryFences }
                    if (-not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath($snapshot.Record.path), $path)) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: module file path alias: $path" }
                    if (-not $allFilePaths.Add([string]$snapshot.Record.path) -or -not $allFileIds.Add(([string]$snapshot.Record.volume_serial_hex + ':' + [string]$snapshot.Record.file_id_hex))) {
                        throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: duplicate or aliased module content file: $path"
                    }
                    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($path, [string]$expectedFiles.Manifest.Record.path)) { $openFiles.Add($snapshot) }
                    $declared = $declaredByPath[[string]$snapshot.Record.path]
                    Assert-D32PowerShellAuthorityFileRecord -Element $declared -Actual $snapshot -Name "module file $($role.Name)"
                    $actualFileRecords.Add($snapshot.Record)
                }
                $inventory = Get-D32PowerShellAuthorityInventoryDigest -Role ([string]$role.Role) -Files $actualFileRecords.ToArray()
                if ((Get-D32PowerShellAuthorityJsonString $moduleElement 'inventory_sha256') -cne $inventory) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: complete deterministic module inventory digest mismatch: $($role.Name)" }
                $moduleRecords.Add([ordered]@{ role = [string]$role.Role; module_name = [string]$role.Name; manifest_path = [IO.Path]::GetFullPath([string]$role.Manifest); inventory_sha256 = $inventory; files = @($actualFileRecords.ToArray()) })
            }
        }
        finally { $authorityDocument.Dispose() }

        Assert-D32PowerShellAuthorityRuntimeSnapshotCurrent -Snapshot $runtimeDistribution -DirectoryFences $directoryFences -OpenFiles $openFiles
        $resolverState = Get-D32PowerShellAuthorityResolverSnapshot -OsSecurityComponents $osSecurity.Components -OsSecurityInventorySha256 $osSecurity.InventorySha256 -ConfigureNativeSearch
        if ($resolverState.Blockers.Count -gt 0) { throw ('POWERSHELL_MODULE_AUTHORITY_BLOCKED: resolver admission failed before import; import_attempts=0; ' + ($resolverState.Blockers -join '; ')) }
        Assert-D32PowerShellAuthorityRuntimeSnapshotCurrent -Snapshot $runtimeDistribution -DirectoryFences $directoryFences -OpenFiles $openFiles
        Assert-D32PowerShellAuthorityOsSecurityComponentsCurrent -Components $osSecurity.Components -DirectoryFences $directoryFences
        $processToken = Get-D32PowerShellAuthorityCurrentToken
        $roles = @(Get-D32PowerShellAuthorityFixedModuleRoles -PowerShellRoot $powerShellRoot)
        $expectedModulePaths = [System.Collections.Generic.Dictionary[string,string[]]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($role in $roles) { $expectedModulePaths[[string]$role.Name] = [string[]](Get-D32PowerShellAuthorityAllowedModulePaths -PowerShellRoot $powerShellRoot -Role $role) }
        $importAttempts = 0
        foreach ($role in $roles) {
            $importAttempts++
            $global:D32PowerShellModuleImportAttempts = $importAttempts
            Microsoft.PowerShell.Core\Import-Module -Name ([IO.Path]::GetFullPath([string]$role.Manifest)) -ErrorAction Stop
        }
        $postImportResolver = Get-D32PowerShellAuthorityResolverSnapshot -OsSecurityComponents $osSecurity.Components -OsSecurityInventorySha256 $osSecurity.InventorySha256 -ConfigureNativeSearch
        $transitionNativeFiles = [System.Collections.Generic.List[object]]::new()
        foreach ($file in $runtimeDistribution.files) { $transitionNativeFiles.Add($file) }
        foreach ($component in $osSecurity.Components) { foreach ($file in @($component.native_files)) { $transitionNativeFiles.Add($file) } }
        $transitionManagedFiles = [System.Collections.Generic.List[object]]::new()
        foreach ($file in $runtimeDistribution.files) { $transitionManagedFiles.Add($file) }
        foreach ($component in $osSecurity.Components) { foreach ($file in @($component.distribution.files)) { $transitionManagedFiles.Add($file) } }
        $resolverTransition = Test-D32PowerShellAuthorityResolverSnapshotTransition -Before $resolverState -After $postImportResolver `
            -PinnedNativeFiles $transitionNativeFiles.ToArray() -PinnedManagedFiles $transitionManagedFiles.ToArray() `
            -PowerShellRoot $powerShellRoot -WindowsRoot ([string]$osSecurity.WindowsRoot) -DefenderRoot ([string]$osSecurity.DefenderRoot)
        if (-not $resolverTransition.Passed) {
            $diagnosticText = ConvertTo-D32PowerShellAuthorityJsonText -Value $resolverTransition.Diagnostic
            throw ('POWERSHELL_MODULE_AUTHORITY_BLOCKED: pre/post-import resolver transition denied; diagnostic=' + $diagnosticText)
        }

        $closureRecords = @($moduleRecords.ToArray())
        $combined = [Text.StringBuilder]::new()
        foreach ($record in $closureRecords) { [void]$combined.Append([string]$record.role).Append('|').Append([string]$record.inventory_sha256).Append("`n") }
        $closureDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes($combined.ToString()))).ToLowerInvariant()
        $moduleRootIdentity = $directoryFences[$moduleRoot]
        $admission = [PSCustomObject][ordered]@{
            record_type = 'D32_POWERSHELL_MODULE_ADMISSION_V2'
            schema_version = 2
            status = 'ADMITTED'
            candidate_sha = $CallerCandidateSha
            source_repo = $repo
            authority_reference = [ordered]@{ path = [string]$authorityFile.Record.path; sha256 = [string]$authorityFile.Record.sha256; bytes = [Int64]$authorityFile.Record.bytes; volume_serial_hex = [string]$authorityFile.Record.volume_serial_hex; file_id_hex = [string]$authorityFile.Record.file_id_hex }
            profile_reference = [ordered]@{ path = [string]$profileFile.Record.path; sha256 = [string]$profileFile.Record.sha256; bytes = [Int64]$profileFile.Record.bytes; volume_serial_hex = [string]$profileFile.Record.volume_serial_hex; file_id_hex = [string]$profileFile.Record.file_id_hex }
            git_image = [ordered]@{ path = [string]$gitFile.Record.path; sha256 = [string]$gitFile.Record.sha256; bytes = [Int64]$gitFile.Record.bytes; volume_serial_hex = [string]$gitFile.Record.volume_serial_hex; file_id_hex = [string]$gitFile.Record.file_id_hex }
            powershell_host = [ordered]@{ path = [string]$hostFile.Record.path; sha256 = [string]$hostFile.Record.sha256; bytes = [Int64]$hostFile.Record.bytes; volume_serial_hex = [string]$hostFile.Record.volume_serial_hex; file_id_hex = [string]$hostFile.Record.file_id_hex; pshome = $powerShellRoot }
            runner_process = [ordered]@{ process_id = $processId; start_time_utc_ticks = $processStartTicks; image_path = [string]$hostFile.Record.path; image_file_id_hex = [string]$hostFile.Record.file_id_hex; token_state = $processToken }
            startup = [ordered]@{ file_operand = [string]$startup.FileOperand; switches = @($startup.Switches); startup_policy = 'DIRECT_NO_PROFILE_FILE_V1' }
            entry_script_path = $entryScript
            module_import_order = @('Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility','CimCmdlets')
            module_closure = [ordered]@{ module_root = $moduleRoot; module_root_volume_serial_hex = [string]$moduleRootIdentity.VolumeSerialHex; module_root_file_id_hex = [string]$moduleRootIdentity.FileIdHex; inventory_sha256 = $closureDigest; modules = $closureRecords; runtime_distribution_sha256 = [string]$runtimeDistribution.inventory_sha256; protected_namespace_sha256 = [string]$runtimeDistribution.inventory_sha256; resolver_sha256 = [string]$postImportResolver.ResolverSha256 }
            resolver_admission = [ordered]@{ state = 'VERIFIED'; policy_id = 'D32_POWERSHELL_RESOLVER_DOMAIN_V2'; resolver_sha256 = [string]$postImportResolver.ResolverSha256; os_security_inventory_sha256 = [string]$postImportResolver.OsSecurityInventorySha256; native_policy = [string]$postImportResolver.NativePolicy; module_search_path = [string]$postImportResolver.ModuleSearchPath; trusted_platform_paths = @($postImportResolver.TrustedPlatformPaths); loaded_managed_assembly_paths = @($postImportResolver.LoadedManagedAssemblyPaths); deps_paths = @($postImportResolver.DepsPaths); native_directories = @($postImportResolver.NativeDirectories); native_module_paths = @($postImportResolver.NativeModulePaths); active_environment = @($postImportResolver.ActiveEnvironment) }
            entry_script = [ordered]@{ path = [string]$entrySnapshot.Record.path; bytes = [Int64]$entrySnapshot.Record.bytes; sha256 = [string]$entrySnapshot.Record.sha256; volume_serial_hex = [string]$entrySnapshot.Record.volume_serial_hex; file_id_hex = [string]$entrySnapshot.Record.file_id_hex }
            import_verification = [ordered]@{ state = 'VERIFIED'; verified_import_count = 3; modules = @(); assemblies = @(); commands = @(); native_modules = @() }
            import_attempts = 3
        }
        $osProtectedFilePaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $osSecurityDirectoryPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $osSecurityAncestorPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($component in $osSecurity.Components) {
            foreach ($fileRecord in @($component.distribution.files)) { [void]$osProtectedFilePaths.Add([string]$fileRecord.path) }
            foreach ($directoryRecord in @($component.distribution.directories)) { [void]$osSecurityDirectoryPaths.Add([string]$directoryRecord.path) }
            foreach ($ancestorRecord in @($component.distribution.protected_ancestors)) { [void]$osSecurityAncestorPaths.Add([string]$ancestorRecord.path) }
        }
        $state = [PSCustomObject]@{
            RepositoryRoot = $repo; PowerShellRoot = $powerShellRoot; ModuleRoot = $moduleRoot; ImportOrder = @('Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility','CimCmdlets')
            ExpectedModuleManifestPaths = $expectedModulePaths; OpenFiles = $openFiles.ToArray(); DirectoryFences = $directoryFences; RuntimeDistribution = $runtimeDistribution; OsSecurityComponents = $osSecurity.Components
            OsSecurityInventorySha256 = [string]$admission.resolver_admission.os_security_inventory_sha256
            OsProtectedFilePaths = $osProtectedFilePaths; OsSecurityDirectoryPaths = $osSecurityDirectoryPaths; OsSecurityAncestorPaths = $osSecurityAncestorPaths; ImportAttempts = $importAttempts
            AuthorityReference = $admission.authority_reference; ProfileReference = $admission.profile_reference; Admission = $admission
            Startup = [PSCustomObject]@{ FileOperand = [string]$admission.startup.file_operand; Switches = [string[]]@($admission.startup.switches) }
        }
        $global:D32PowerShellModuleAuthorityState = $state
        $moduleInfos = @(Microsoft.PowerShell.Core\Get-Module)
        foreach ($role in $roles) {
            $matches = @($moduleInfos | Where-Object { [string]$_.Name -ceq [string]$role.Name })
            if ($matches.Count -ne 1 -or [string]$matches[0].Path -cnotin $expectedModulePaths[[string]$role.Name]) {
                throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: imported module identity is missing, duplicated, or not exact: $($role.Name)"
            }
            $admission.import_verification.modules += [ordered]@{ name = [string]$matches[0].Name; path = [IO.Path]::GetFullPath([string]$matches[0].Path); version = [string]$matches[0].Version }
        }
        $assemblies = [System.Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($assembly in [AppDomain]::CurrentDomain.GetAssemblies()) {
            $location = ''
            try { $location = [IO.Path]::GetFullPath([string]$assembly.Location) } catch { continue }
            foreach ($moduleRecord in $closureRecords) {
                foreach ($fileRecord in $moduleRecord.files) {
                    if ([StringComparer]::OrdinalIgnoreCase.Equals($location, [string]$fileRecord.path)) {
                        $assemblies[$location] = [ordered]@{ path = $location; sha256 = [string]$fileRecord.sha256; bytes = [Int64]$fileRecord.bytes; volume_serial_hex = [string]$fileRecord.volume_serial_hex; file_id_hex = [string]$fileRecord.file_id_hex }
                    }
                }
            }
        }
        $admission.import_verification.assemblies = @($assemblies.Values)
        foreach ($assemblyPath in (Get-D32PowerShellAuthorityFixedImportAssemblyPaths -PowerShellRoot $powerShellRoot)) {
            if (-not $assemblies.ContainsKey([IO.Path]::GetFullPath([string]$assemblyPath))) {
                throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: a fixed RootModule/NestedModule/RequiredAssembly did not load from its admitted closure: $assemblyPath"
            }
        }
        $nativeEvidence = Get-D32PowerShellAuthorityNativeOriginEvidence -ResolverSnapshot $postImportResolver -RuntimeDistributionFiles $runtimeDistribution.files `
            -OsSecurityComponents $osSecurity.Components -PowerShellRoot $powerShellRoot
        $admission.import_verification.native_modules = @($nativeEvidence)
        Assert-D32PowerShellModuleAdmissionCurrent -State $state
        if (-not (Test-D32PowerShellModuleAdmissionRecord -Document $admission -CandidateSha $CallerCandidateSha -Repository $repo)) { throw "POWERSHELL_MODULE_AUTHORITY_BLOCKED: generated shared module-admission record failed its strict self-validation; validator_context=$script:D32PowerShellModuleAdmissionValidationContext" }
        $global:D32PowerShellModuleImportAttempts = $importAttempts
        return $admission
    }
    catch {
        $global:D32PowerShellModuleAuthorityState = $null
        $global:D32PowerShellModuleImportAttempts = $importAttempts
        foreach ($file in $openFiles) { if ($null -ne $file.Stream -and -not $file.Stream.SafeFileHandle.IsClosed) { $file.Stream.Dispose() } }
        foreach ($directory in $directoryFences.Values) { if ($null -ne $directory.Handle -and -not $directory.Handle.IsClosed) { $directory.Handle.Dispose() } }
        throw
    }
}
