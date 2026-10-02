# Module-free focused regression checks for the V2 debug-trace root identity boundary.
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath([IO.Path]::Combine($PSScriptRoot, '..'))
$phase0Path = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'd32-phase0-matrix.ps1'))
$fixturePath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'd32-fixture-prebuild.ps1'))
$profilePath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'd32-build-toolchain-profile.ps1'))
$moduleStart = @(Microsoft.PowerShell.Core\Get-Module | ForEach-Object { '{0}|{1}|{2}' -f $_.Name, $_.Version, $_.Path } | Sort-Object)
$global:D32PowerShellModuleImportAttempts = 0
$script:cases = [System.Collections.Generic.List[object]]::new()
$script:failures = [System.Collections.Generic.List[string]]::new()

function Import-D32TraceIdentitySelfTestFunction {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Name)
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) { throw "SELFTEST_BLOCKED: source parse failed for $Path" }
    $functionAst = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $Name }, $true)
    if ($null -eq $functionAst) { throw "SELFTEST_BLOCKED: function was not found: $Name" }
    return $functionAst.Body.GetScriptBlock()
}

function Add-D32TraceIdentitySelfTestCase {
    param([Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)][bool]$Passed, [AllowNull()][string]$Detail = $null)
    $script:cases.Add([PSCustomObject]@{ name = $Name; passed = $Passed; detail = $Detail })
    if (-not $Passed) { $script:failures.Add($Name) }
}

function Get-D32Phase0FileReference {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    if (-not (Test-D32ProfileNoReparsePath -Path $full)) { throw 'SELFTEST_BLOCKED: diagnostic test file is missing or reparse-backed' }
    $bytes = [IO.File]::ReadAllBytes($full)
    $sha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
    return [ordered]@{
        path = $full; bytes = [Int64]$bytes.LongLength; sha256 = $sha
        volume_serial_hex = '0000000000000001'; file_id_hex = ('1' * 32)
    }
}

function Test-D32Phase0OwnerBinding {
    param(
        [Parameter(Mandatory = $true)][string]$EvidenceRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedCandidateSha,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][string]$ExpectedRunId,
        [Parameter(Mandatory = $true)][object]$ExpectedRootIdentity,
        [Parameter(Mandatory = $true)][object]$ExpectedMarkerReference
    )
    $context = $script:D32Phase0FailureContext
    if ($null -eq $context -or $EvidenceRoot -cne $context.EvidenceRoot -or
        $ExpectedCandidateSha -cne $context.CandidateSha -or $ExpectedRunId -cne $context.RunId -or
        $ValidatedProfile.Digest -cne $context.Profile.Digest -or
        $ExpectedRootIdentity.FileIdHex -cne $context.RootIdentity.FileIdHex -or
        $ExpectedMarkerReference.sha256 -cne $context.OwnerMarker.sha256) {
        throw 'SELFTEST_BLOCKED: diagnostic test writer received a mismatched synthetic owner context'
    }
    return [PSCustomObject]@{
        EvidenceRootIdentity = $context.RootIdentity
        MarkerReference = $context.OwnerMarker
        RunId = $context.RunId
    }
}

function Copy-D32TraceIdentitySelfTestShape {
    param([Parameter(Mandatory = $true)][object]$Value)
    return ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $Value -Depth 20 -Compress) -DateKind String
}

function Copy-D32DebugCommandLineCaptureSelfTestShape {
    param([Parameter(Mandatory = $true)][object]$Value)
    $capture = $Value.CommandLineCapture
    return [PSCustomObject][ordered]@{
        ProcessId = [uint32]$Value.ProcessId
        ParentProcessId = [uint32]$Value.ParentProcessId
        CreationFileTime = [Int64]$Value.CreationFileTime
        ParentCreationFileTime = [Int64]$Value.ParentCreationFileTime
        ImagePath = [string]$Value.ImagePath
        Bytes = [Int64]$Value.Bytes
        Sha256 = [string]$Value.Sha256
        VolumeSerialHex = [string]$Value.VolumeSerialHex
        FileIdHex = [string]$Value.FileIdHex
        ImageVerified = [bool]$Value.ImageVerified
        Exited = [bool]$Value.Exited
        CreatedAtUtc = [string]$Value.CreatedAtUtc
        CommandLineCapture = [PSCustomObject][ordered]@{
            Source = [string]$capture.Source
            ProcessId = [uint32]$capture.ProcessId
            CreationFileTime = [Int64]$capture.CreationFileTime
            ParentProcessId = [uint32]$capture.ParentProcessId
            ParentCreationFileTime = [Int64]$capture.ParentCreationFileTime
            ImagePath = [string]$capture.ImagePath
            Bytes = [Int64]$capture.Bytes
            Sha256 = [string]$capture.Sha256
            VolumeSerialHex = [string]$capture.VolumeSerialHex
            FileIdHex = [string]$capture.FileIdHex
            CommandLine = [string]$capture.CommandLine
        }
    }
}

function Get-D32Phase0AllowedChildImageReason {
    param(
        [Parameter(Mandatory = $true)][string]$ImagePath,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$ExpectedRootPath,
        [AllowNull()][object]$ImageIdentity,
        [AllowNull()][object]$VendoredProtocGrant,
        [AllowNull()][object]$H7CGitRunGrant
    )
    $matches = @($ValidatedProfile.ExecutableInventory + $ValidatedProfile.WindowsImageInventory | Where-Object {
        (Test-D32ProfilePathEqual -Left $_.Path -Right $ImagePath) -and
        $_.Sha256 -ceq $ImageIdentity.sha256 -and [Int64]$_.Bytes -eq [Int64]$ImageIdentity.bytes -and
        $_.VolumeSerialHex -ceq $ImageIdentity.volume_serial_hex -and $_.FileIdHex -ceq $ImageIdentity.file_id_hex
    })
    if ($matches.Count -eq 1) { return 'module-free-selftest-exact-child-pin' }
    return $null
}

foreach ($entry in @(
        [PSCustomObject]@{ Path = $profilePath; Name = 'Get-D32ProfileFullPath' },
        [PSCustomObject]@{ Path = $profilePath; Name = 'Test-D32ProfileCanonicalPathString' },
        [PSCustomObject]@{ Path = $profilePath; Name = 'Test-D32ProfilePathEqual' },
        [PSCustomObject]@{ Path = $profilePath; Name = 'Test-D32ProfilePathWithin' },
        [PSCustomObject]@{ Path = $profilePath; Name = 'Test-D32ProfileNoReparsePath' },
        [PSCustomObject]@{ Path = $phase0Path; Name = 'Test-D32Phase0ExactProperties' },
        [PSCustomObject]@{ Path = $phase0Path; Name = 'Test-D32Phase0Integer' },
        [PSCustomObject]@{ Path = $phase0Path; Name = 'Test-D32Phase0DirectoryEntryExists' },
        [PSCustomObject]@{ Path = $phase0Path; Name = 'Get-D32Phase0ActualDebugCommandLine' },
        [PSCustomObject]@{ Path = $phase0Path; Name = 'Get-D32Phase0DiscoveryFailureEvidence' },
        [PSCustomObject]@{ Path = $phase0Path; Name = 'ConvertFrom-D32Phase0DebugProcess' },
        [PSCustomObject]@{ Path = $phase0Path; Name = 'Get-D32Phase0DiagnosticPropertyValue' },
        [PSCustomObject]@{ Path = $phase0Path; Name = 'Write-D32Phase0BlockedDiagnostic' },
        [PSCustomObject]@{ Path = $phase0Path; Name = 'Assert-D32Phase0DiscoveryNoBlockedDiagnostic' },
        [PSCustomObject]@{ Path = $phase0Path; Name = 'ConvertTo-D32Phase0ExpectedRootIdentity' },
        [PSCustomObject]@{ Path = $phase0Path; Name = 'ConvertTo-D32Phase0DebugProcessTraceDocument' },
        [PSCustomObject]@{ Path = $phase0Path; Name = 'New-D32Phase0SelfTestDebugTrace' },
        [PSCustomObject]@{ Path = $phase0Path; Name = 'Test-D32Phase0DebugProcessTrace' },
        [PSCustomObject]@{ Path = $fixturePath; Name = 'Get-D32ObjectFieldNames' },
        [PSCustomObject]@{ Path = $fixturePath; Name = 'Test-D32FixtureExactProperties' },
        [PSCustomObject]@{ Path = $fixturePath; Name = 'New-D32ProcessIdentityRecord' },
        [PSCustomObject]@{ Path = $fixturePath; Name = 'Get-D32FixtureDebugProcessCommandLine' },
        [PSCustomObject]@{ Path = $fixturePath; Name = 'ConvertFrom-D32DebugProcessRecord' }
    )) {
    Set-Item -Path ('Function:script:{0}' -f $entry.Name) -Value (Import-D32TraceIdentitySelfTestFunction -Path $entry.Path -Name $entry.Name)
}
$script:D32Phase0BlockedDiagnosticName = 'D32-PHASE0-BLOCKED-DIAGNOSTIC.json'

$capturePath = [IO.Path]::GetFullPath('E:\d32\synthetic-cargo.exe')
$captureLine = '"E:\d32\synthetic-cargo.exe" fetch --locked --manifest-path "E:\d32\synthetic repo\Cargo.toml"'
$capture = [PSCustomObject][ordered]@{
    Source = 'CREATE_PROCESS_DEBUG_EVENT.hProcess/PEB.ProcessParameters.CommandLine'
    ProcessId = [uint32]41001
    CreationFileTime = [Int64]133000000000000001
    ParentProcessId = [uint32]41000
    ParentCreationFileTime = [Int64]133000000000000000
    ImagePath = $capturePath
    Bytes = [Int64]100
    Sha256 = 'a' * 64
    VolumeSerialHex = '0000000000000001'
    FileIdHex = '1' * 32
    CommandLine = $captureLine
}
$nativeProcess = [PSCustomObject][ordered]@{
    ProcessId = [uint32]41001; ParentProcessId = [uint32]41000
    CreationFileTime = [Int64]133000000000000001; ParentCreationFileTime = [Int64]133000000000000000
    ImagePath = $capturePath; Bytes = [Int64]100; Sha256 = 'a' * 64
    VolumeSerialHex = '0000000000000001'; FileIdHex = '1' * 32
    ImageVerified = $true; Exited = $true; CreatedAtUtc = [DateTime]::FromFileTimeUtc(133000000000000001L).ToString('o')
    CommandLineCapture = $capture
}
$capturedChildCommandLine = $false
try {
    $capturedChildCommandLine = (Get-D32Phase0ActualDebugCommandLine -Process $nativeProcess) -ceq $captureLine
}
catch { }
Add-D32TraceIdentitySelfTestCase -Name 'child command line comes from exact in-memory PEB capture rather than an expected-argv substitute' -Passed $capturedChildCommandLine
$capturedRootCommandLine = $false
try {
    $rootProxy = ConvertFrom-D32Phase0DebugProcess -Process $nativeProcess -ExpectedCommandLine $captureLine
    $capturedRootCommandLine = $rootProxy.command_line -ceq $captureLine
}
catch { }
Add-D32TraceIdentitySelfTestCase -Name 'root converter separately compares the actual PEB line to caller-fixed root command' -Passed $capturedRootCommandLine
$wrongExpectedCommandRejected = $false
try { $null = ConvertFrom-D32Phase0DebugProcess -Process $nativeProcess -ExpectedCommandLine ($captureLine + ' --wrong') }
catch { $wrongExpectedCommandRejected = $_.Exception.Message -like 'PHASE0_PROCESS_IDENTITY_BLOCKED:*fixed root command*' }
Add-D32TraceIdentitySelfTestCase -Name 'root converter rejects caller command-line mismatch without substituting caller text' -Passed $wrongExpectedCommandRejected

$fixtureCommandLineAccepted = $false
$fixtureIdentityRecord = $null
try {
    $fixtureCommandLineAccepted = (Get-D32FixtureDebugProcessCommandLine -Process $nativeProcess) -ceq $captureLine
    $fixtureIdentityRecord = ConvertFrom-D32DebugProcessRecord -Process $nativeProcess
}
catch { }
Add-D32TraceIdentitySelfTestCase -Name 'fixture descendant converter carries the captured PEB line into the process identity record' `
    -Passed ($fixtureCommandLineAccepted -and $null -ne $fixtureIdentityRecord -and $fixtureIdentityRecord.CommandLine -ceq $captureLine -and $fixtureIdentityRecord.IdentityVerified)
$wrongFixtureExpectedRejected = $false
try { $null = ConvertFrom-D32DebugProcessRecord -Process $nativeProcess -ExpectedCommandLine ($captureLine + ' --wrong') }
catch { $wrongFixtureExpectedRejected = $_.Exception.Message -like 'DEBUG_PROCESS_TRACE_BLOCKED:*fixed root command*' }
Add-D32TraceIdentitySelfTestCase -Name 'fixture root converter rejects caller command-line mismatch without substituting expected argv' -Passed $wrongFixtureExpectedRejected
$fastExitRecord = ConvertFrom-D32DebugProcessRecord -Process $nativeProcess
Add-D32TraceIdentitySelfTestCase -Name 'fast-exited child retains its pre-Continue captured command line and exact exited identity' `
    -Passed ($nativeProcess.Exited -and $fastExitRecord.IdentityVerified -and $fastExitRecord.CommandLine -ceq $captureLine)

foreach ($case in @(
        [PSCustomObject]@{ Name = 'PID'; Mutate = { param($p) $p.CommandLineCapture.ProcessId++ } },
        [PSCustomObject]@{ Name = 'PID type'; Mutate = { param($p) $p.CommandLineCapture.ProcessId = [Int64]$p.CommandLineCapture.ProcessId } },
        [PSCustomObject]@{ Name = 'creation time'; Mutate = { param($p) $p.CommandLineCapture.CreationFileTime++ } },
        [PSCustomObject]@{ Name = 'creation time type'; Mutate = { param($p) $p.CommandLineCapture.CreationFileTime = [string]$p.CommandLineCapture.CreationFileTime } },
        [PSCustomObject]@{ Name = 'parent PID'; Mutate = { param($p) $p.CommandLineCapture.ParentProcessId++ } },
        [PSCustomObject]@{ Name = 'parent creation time'; Mutate = { param($p) $p.CommandLineCapture.ParentCreationFileTime++ } },
        [PSCustomObject]@{ Name = 'opened image path'; Mutate = { param($p) $p.CommandLineCapture.ImagePath = [IO.Path]::GetFullPath('E:\d32\other.exe') } },
        [PSCustomObject]@{ Name = 'opened image bytes'; Mutate = { param($p) $p.CommandLineCapture.Bytes++ } },
        [PSCustomObject]@{ Name = 'opened image hash'; Mutate = { param($p) $p.CommandLineCapture.Sha256 = 'b' * 64 } },
        [PSCustomObject]@{ Name = 'opened image volume'; Mutate = { param($p) $p.CommandLineCapture.VolumeSerialHex = '0000000000000002' } },
        [PSCustomObject]@{ Name = 'opened image file ID'; Mutate = { param($p) $p.CommandLineCapture.FileIdHex = '2' * 32 } },
        [PSCustomObject]@{ Name = 'capture source'; Mutate = { param($p) $p.CommandLineCapture.Source = 'caller-supplied-argv' } },
        [PSCustomObject]@{ Name = 'empty actual line'; Mutate = { param($p) $p.CommandLineCapture.CommandLine = '' } },
        [PSCustomObject]@{ Name = 'unknown capture field'; Mutate = { param($p) $p.CommandLineCapture | Add-Member -NotePropertyName Unapproved -NotePropertyValue $true } }
    )) {
    $mutatedProcess = Copy-D32DebugCommandLineCaptureSelfTestShape -Value $nativeProcess
    & $case.Mutate $mutatedProcess
    $rejected = $false
    try { $null = Get-D32Phase0ActualDebugCommandLine -Process $mutatedProcess }
    catch { $rejected = $_.Exception.Message -like 'PHASE0_PROCESS_IDENTITY_BLOCKED:*' }
    Add-D32TraceIdentitySelfTestCase -Name "actual command-line capture rejects $($case.Name) drift" -Passed $rejected
    $fixtureRejected = $false
    try { $null = Get-D32FixtureDebugProcessCommandLine -Process $mutatedProcess }
    catch { $fixtureRejected = $_.Exception.Message -like 'DEBUG_PROCESS_TRACE_BLOCKED:*' }
    Add-D32TraceIdentitySelfTestCase -Name "fixture command-line capture rejects $($case.Name) drift" -Passed $fixtureRejected
}
$processRecordMutations = @(
    [PSCustomObject]@{ Name = 'PID'; Mutate = { param($p) $p.ProcessId++ } },
    [PSCustomObject]@{ Name = 'creation time'; Mutate = { param($p) $p.CreationFileTime++ } },
    [PSCustomObject]@{ Name = 'parent PID'; Mutate = { param($p) $p.ParentProcessId++ } },
    [PSCustomObject]@{ Name = 'parent creation time'; Mutate = { param($p) $p.ParentCreationFileTime++ } },
    [PSCustomObject]@{ Name = 'opened image path'; Mutate = { param($p) $p.ImagePath = [IO.Path]::GetFullPath('E:\d32\other.exe') } },
    [PSCustomObject]@{ Name = 'opened image bytes'; Mutate = { param($p) $p.Bytes++ } },
    [PSCustomObject]@{ Name = 'opened image hash'; Mutate = { param($p) $p.Sha256 = 'b' * 64 } },
    [PSCustomObject]@{ Name = 'opened image volume'; Mutate = { param($p) $p.VolumeSerialHex = '0000000000000002' } },
    [PSCustomObject]@{ Name = 'opened image file ID'; Mutate = { param($p) $p.FileIdHex = '2' * 32 } },
    [PSCustomObject]@{ Name = 'unverified opened image'; Mutate = { param($p) $p.ImageVerified = $false } }
)
foreach ($case in $processRecordMutations) {
    $mutatedProcess = Copy-D32DebugCommandLineCaptureSelfTestShape -Value $nativeProcess
    & $case.Mutate $mutatedProcess
    $phase0Rejected = $false
    try { $null = Get-D32Phase0ActualDebugCommandLine -Process $mutatedProcess }
    catch { $phase0Rejected = $_.Exception.Message -like 'PHASE0_PROCESS_IDENTITY_BLOCKED:*' }
    Add-D32TraceIdentitySelfTestCase -Name "Phase0 rejects process record $($case.Name) drift against its captured PEB identity" -Passed $phase0Rejected
    $fixtureRejected = $false
    try { $null = Get-D32FixtureDebugProcessCommandLine -Process $mutatedProcess }
    catch { $fixtureRejected = $_.Exception.Message -like 'DEBUG_PROCESS_TRACE_BLOCKED:*' }
    Add-D32TraceIdentitySelfTestCase -Name "fixture rejects process record $($case.Name) drift against its captured PEB identity" -Passed $fixtureRejected
}
$unexitedProcess = Copy-D32DebugCommandLineCaptureSelfTestShape -Value $nativeProcess
$unexitedProcess.Exited = $false
$phase0UnexitedRejected = $false
try { $null = Get-D32Phase0ActualDebugCommandLine -Process $unexitedProcess }
catch { $phase0UnexitedRejected = $_.Exception.Message -like 'PHASE0_PROCESS_IDENTITY_BLOCKED:*' }
$fixtureUnexitedRejected = $false
try { $null = Get-D32FixtureDebugProcessCommandLine -Process $unexitedProcess }
catch { $fixtureUnexitedRejected = $_.Exception.Message -like 'DEBUG_PROCESS_TRACE_BLOCKED:*' }
Add-D32TraceIdentitySelfTestCase -Name 'process identity projection refuses a CREATE capture until matching EXIT evidence is present' `
    -Passed ($phase0UnexitedRejected -and $fixtureUnexitedRejected)
$missingCaptureFields = [ordered]@{}
foreach ($property in $nativeProcess.PSObject.Properties) {
    if ($property.Name -cne 'CommandLineCapture') { $missingCaptureFields[$property.Name] = $property.Value }
}
$missingCapture = [PSCustomObject]$missingCaptureFields
$missingCaptureRejected = $false
try { $null = Get-D32Phase0ActualDebugCommandLine -Process $missingCapture }
catch { $missingCaptureRejected = $_.Exception.Message -like '*actual CREATE command-line capture is missing*' }
Add-D32TraceIdentitySelfTestCase -Name 'actual command-line capture rejects absent or fast-exit-unreadable PEB evidence' -Passed $missingCaptureRejected
$fixtureMissingCaptureRejected = $false
try { $null = Get-D32FixtureDebugProcessCommandLine -Process $missingCapture }
catch { $fixtureMissingCaptureRejected = $_.Exception.Message -like '*actual CREATE command-line capture is missing*' }
Add-D32TraceIdentitySelfTestCase -Name 'fixture command-line capture rejects absent or fast-exit-unreadable PEB evidence' -Passed $fixtureMissingCaptureRejected

$fixtureSourcePath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'd32-fixture-prebuild.ps1'))
$fixtureSource = [IO.File]::ReadAllText($fixtureSourcePath, [Text.UTF8Encoding]::new($false, $true))
$nativeCaptureIndex = $fixtureSource.IndexOf('commandLineCapture = CaptureDebugCommandLine(created.Process, ev.ProcessId, creation, parentPid, parentCreation, image)', [StringComparison]::Ordinal)
$nativeBeforeContinueIndex = $fixtureSource.IndexOf('VerifyCreateCommandLineCaptureBeforeContinue(created.Process', [StringComparison]::Ordinal)
$nativeContinueIndex = $fixtureSource.IndexOf('ContinueDebugEvent(ev.ProcessId, ev.ThreadId, continueStatus)', [StringComparison]::Ordinal)
$serializerAstTokens = $null; $serializerAstErrors = $null
$fixtureAst = [System.Management.Automation.Language.Parser]::ParseFile($fixtureSourcePath, [ref]$serializerAstTokens, [ref]$serializerAstErrors)
$traceSerializer = $fixtureAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'ConvertTo-D32DebugProcessTraceDocument' }, $true)
$phase0SourceTokens = $null; $phase0SourceErrors = $null
$phase0Ast = [System.Management.Automation.Language.Parser]::ParseFile($phase0Path, [ref]$phase0SourceTokens, [ref]$phase0SourceErrors)
$phase0Serializer = $phase0Ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'ConvertTo-D32Phase0DebugProcessTraceDocument' }, $true)
$wireSerializersDoNotExtendV2 = $null -ne $traceSerializer -and $fixtureAst -and $fixtureAst.EndBlock.Statements.Count -gt 0 -and
    $null -ne $phase0Serializer -and $traceSerializer.Extent.Text -notmatch '(?i)CommandLineCapture|command_line' -and
    $phase0Serializer.Extent.Text -notmatch '(?i)CommandLineCapture|command_line' -and
    $nativeCaptureIndex -ge 0 -and $nativeBeforeContinueIndex -gt $nativeCaptureIndex -and $nativeContinueIndex -gt $nativeBeforeContinueIndex -and
    $fixtureSource.Contains('ReadRemoteUnicodeString(eventProcessHandle, IntPtr.Add(parameters, 0x70), "CommandLine")') -and
    $fixtureSource.Contains('VerifyRetainedDebugParentIdentity(retainedCurrent.Handle, record.ProcessId, record.CreationFileTime') -and
    $fixtureSource.Contains('CaptureDebugCommandLine(eventProcessHandle, record.ProcessId,') -and
    $fixtureSource.Contains('record.ParentCreationFileTime, openedImage)') -and
    $fixtureSource.Contains('CREATE retained parent identity chain contains a cycle') -and
    $fixtureSource.Contains('cursor.ParentCreationFileTime != debuggerCreation')
Add-D32TraceIdentitySelfTestCase -Name 'native CREATE PEB capture and retained child/parent revalidation precede Continue while frozen V2 wire schema stays unchanged' -Passed $wireSerializersDoNotExtendV2

$diagnosticRoot = [IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath()) ('d32-phase0-diagnostic-probe-' + [Guid]::NewGuid().ToString('N'))))
if ([IO.Directory]::Exists($diagnosticRoot) -or [IO.File]::Exists($diagnosticRoot)) { throw 'SELFTEST_BLOCKED: synthetic diagnostic probe root collision' }
[void][IO.Directory]::CreateDirectory($diagnosticRoot)
$diagnosticPath = Join-Path $diagnosticRoot $script:D32Phase0BlockedDiagnosticName
$stdoutCapturePath = Join-Path $diagnosticRoot 'synthetic-fixed-command.stdout.log'
$oldFailureContextVariable = Get-Variable -Name D32Phase0FailureContext -Scope Script -ErrorAction SilentlyContinue
$oldFailureContext = if ($null -eq $oldFailureContextVariable) { $null } else { $oldFailureContextVariable.Value }
$script:D32Phase0BlockedDiagnosticType = 'D32_PHASE0_BLOCKED_DIAGNOSTIC_V1'
$diagnosticProfile = [PSCustomObject]@{
    ProfilePath = 'E:\d32\synthetic-profile.json'
    Digest = 'b' * 64
    Identity = [PSCustomObject]@{ Bytes = [Int64]100; VolumeSerialHex = '0000000000000001'; FileIdHex = '2' * 32 }
}
$diagnosticRootIdentity = [PSCustomObject]@{
    Path = $diagnosticRoot; VolumeSerialHex = '0000000000000001'; FileIdHex = '3' * 32
}
$diagnosticOwnerMarker = [ordered]@{
    path = Join-Path $diagnosticRoot 'D32-PHASE0-OWNER.json'; bytes = [Int64]1
    sha256 = 'c' * 64; volume_serial_hex = '0000000000000001'; file_id_hex = '4' * 32
}
$script:D32Phase0FailureContext = [PSCustomObject]@{
    EvidenceRoot = $diagnosticRoot; CandidateSha = 'a' * 40; Profile = $diagnosticProfile
    RunId = 'd' * 32; RootIdentity = $diagnosticRootIdentity; OwnerMarker = $diagnosticOwnerMarker
}
$diagnosticCommand = [ordered]@{ name = 'selftest-fixed-fetch'; arguments = @('fetch', '--locked') }
$diagnosticIdentity = [ordered]@{ process_id = 41001; parent_process_id = 41000; identity_verified = $false }
$incompleteTrace = [ordered]@{
    event_chain_complete = $false; debugger_thread_joined = $true; retained_process_handles_signaled = $false
    debugger_association_query_verified = $true; debugger_association_absent = $true
    job_accounting_verified = $false; accounting_consistent = $false; job_active_processes = 2
}
$incompleteCleanup = [ordered]@{
    CleanupSucceeded = $false; JobCloseSucceeded = $true; JobActiveProcessCountVerified = $false
    JobActiveProcessCount = 2; DebuggerThreadJoined = $true; RetainedProcessHandlesSignaled = $false
    DebuggerAssociationQueryVerified = $true; DebuggerAssociationAbsent = $true
}
$script:D32Phase0LastProcessFailure = $null
$script:D32Phase0LastProcessEvidence = [ordered]@{
    PrimaryError = $null
    Command = [ordered]@{ name = 'completed-prior-command' }
    ProcessIdentity = [ordered]@{ identity_verified = $true }
    RawV2Trace = [ordered]@{ event_chain_complete = $true }
    NativeCleanup = [ordered]@{ CleanupSucceeded = $true }
    StdoutPath = 'E:\d32\prior.stdout.log'
    StderrPath = 'E:\d32\prior.stderr.log'
}
$staleCommandEvidenceRejected = $null -eq (Get-D32Phase0DiscoveryFailureEvidence)
$script:D32Phase0LastProcessFailure = [ordered]@{ PrimaryError = 'current fixed-command failure'; Command = [ordered]@{ name = 'current-failing-command' } }
$currentCommandEvidenceRetained = (Get-D32Phase0DiscoveryFailureEvidence).Command.name -ceq 'current-failing-command'
Add-D32TraceIdentitySelfTestCase -Name 'discovery failure context never misattributes a previously completed command but retains the current failed command' `
    -Passed ($staleCommandEvidenceRejected -and $currentCommandEvidenceRetained)
try {
    $noDiagnosticAccepted = $false
    try { $noDiagnosticAccepted = Assert-D32Phase0DiscoveryNoBlockedDiagnostic -EvidenceRoot $diagnosticRoot }
    catch { }
    Add-D32TraceIdentitySelfTestCase -Name 'discovery-root consumer allows absence of failure-only diagnostic' -Passed $noDiagnosticAccepted
    $stdoutBytes = [Text.UTF8Encoding]::new($false).GetBytes("synthetic stdout`n")
    $stdoutStream = [IO.File]::Open($stdoutCapturePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $stdoutStream.Write($stdoutBytes, 0, $stdoutBytes.Length); $stdoutStream.Flush($true) } finally { $stdoutStream.Dispose() }
    $writeFailure = $null
    try {
        $diagnosticPath = Write-D32Phase0BlockedDiagnostic -PrimaryError 'synthetic primary fetch/list failure' `
            -SecondaryErrors @('synthetic cleanup failure', 'synthetic secondary orchestration failure') `
            -Command $diagnosticCommand -ProcessIdentity $diagnosticIdentity -RawV2Trace $incompleteTrace `
            -NativeCleanup $incompleteCleanup -StdoutPath $stdoutCapturePath -StderrPath $null
    }
    catch { $writeFailure = $_.Exception.Message }
    $diagnostic = if ($null -eq $writeFailure) { [IO.File]::ReadAllText($diagnosticPath, [Text.Encoding]::UTF8) | ConvertFrom-Json } else { $null }
    $diagnosticPreserved = $null -ne $diagnostic -and
        $diagnostic.schema_version -eq 1 -and $diagnostic.record_type -ceq 'D32_PHASE0_BLOCKED_DIAGNOSTIC_V1' -and
        $diagnostic.status -ceq 'BLOCKED' -and $diagnostic.gate_authority -ceq 'NONE' -and
        $diagnostic.phase1_allowed -eq $false -and $diagnostic.aggregate_allowed -eq $false -and
        $diagnostic.candidate_sha -ceq ('a' * 40) -and $diagnostic.toolchain_profile.sha256 -ceq ('b' * 64) -and
        $diagnostic.evidence_root.path -ceq $diagnosticRoot -and $diagnostic.run_id -ceq ('d' * 32) -and
        $diagnostic.primary_error -ceq 'synthetic primary fetch/list failure' -and
        ($diagnostic.secondary_errors -join "`0") -ceq "synthetic cleanup failure`0synthetic secondary orchestration failure" -and
        $diagnostic.failing_fixed_command.name -ceq 'selftest-fixed-fetch' -and
        $diagnostic.process_identity.identity_verified -eq $false -and
        $diagnostic.raw_v2_trace.event_chain_complete -eq $false -and
        $diagnostic.job_debug_cleanup.raw_native_cleanup.CleanupSucceeded -eq $false -and
        $diagnostic.job_debug_cleanup.verification -ceq 'UNVERIFIED' -and
        @($diagnostic.job_debug_cleanup.unverified_fields | Where-Object { $_ -ceq 'cleanup.CleanupSucceeded' -or $_ -ceq 'cleanup.JobActiveProcessCountVerified' -or $_ -ceq 'trace.event_chain_complete' }).Count -eq 3 -and
        $diagnostic.ordered_stream_captures.Count -eq 2 -and
        $diagnostic.ordered_stream_captures[0].ordinal -eq 1 -and $diagnostic.ordered_stream_captures[0].stream -ceq 'stdout' -and
        $diagnostic.ordered_stream_captures[0].status -ceq 'CAPTURED' -and
        $diagnostic.ordered_stream_captures[0].path -ceq $stdoutCapturePath -and
        $diagnostic.ordered_stream_captures[0].reference.bytes -eq $stdoutBytes.Length -and
        $diagnostic.ordered_stream_captures[0].reference.sha256 -ceq (Get-D32Phase0FileReference -Path $stdoutCapturePath).sha256 -and
        $diagnostic.ordered_stream_captures[1].ordinal -eq 2 -and $diagnostic.ordered_stream_captures[1].stream -ceq 'stderr' -and
        $diagnostic.ordered_stream_captures[1].status -ceq 'UNAVAILABLE' -and $null -eq $diagnostic.ordered_stream_captures[1].reference -and
        @($diagnostic.unverified_fields | Where-Object { $_ -ceq 'stream.stderr' }).Count -eq 1
    Add-D32TraceIdentitySelfTestCase -Name 'failure-only diagnostic create-new preserves primary/secondary errors and exact candidate/profile/root/run with incomplete cleanup explicitly UNVERIFIED' -Passed $diagnosticPreserved -Detail $writeFailure

    $diagnosticRejected = $false
    try { $null = Assert-D32Phase0DiscoveryNoBlockedDiagnostic -EvidenceRoot $diagnosticRoot }
    catch { $diagnosticRejected = $_.Exception.Message -like 'TEST_INVENTORY_DISCOVERY_BLOCKED:*blocked-diagnostic sidecar exists*' }
    Add-D32TraceIdentitySelfTestCase -Name 'discovery-root consumer refuses a generated blocked diagnostic regardless of cleanup claim' -Passed $diagnosticRejected

    $beforeCollision = if ([IO.File]::Exists($diagnosticPath)) { (Get-D32Phase0FileReference -Path $diagnosticPath).sha256 } else { $null }
    $overwriteRejected = $false
    try { $null = Write-D32Phase0BlockedDiagnostic -PrimaryError 'replacement failure' }
    catch { $overwriteRejected = $_.Exception.Message -like '*refusing to overwrite an existing blocked-diagnostic sidecar*' }
    $afterCollision = if ([IO.File]::Exists($diagnosticPath)) { (Get-D32Phase0FileReference -Path $diagnosticPath).sha256 } else { $null }
    Add-D32TraceIdentitySelfTestCase -Name 'failure-only diagnostic create-new refuses collision without replacing original bytes' `
        -Passed ($overwriteRejected -and $beforeCollision -ceq $afterCollision -and $null -ne $beforeCollision)

    [IO.File]::WriteAllText($diagnosticPath, '{"schema_version":2,"record_type":"D32_PHASE0_BLOCKED_DIAGNOSTIC_V1","status":"PASS","gate_authority":"PASS","unexpected_schema_field":true}', [Text.UTF8Encoding]::new($false))
    $unknownSchemaRejected = $false
    try { $null = Assert-D32Phase0DiscoveryNoBlockedDiagnostic -EvidenceRoot $diagnosticRoot }
    catch { $unknownSchemaRejected = $_.Exception.Message -like 'TEST_INVENTORY_DISCOVERY_BLOCKED:*blocked-diagnostic sidecar exists*' }
    Add-D32TraceIdentitySelfTestCase -Name 'discovery-root consumer rejects unknown-schema and forged-PASS sidecars before parsing' -Passed $unknownSchemaRejected

    [IO.File]::Delete($diagnosticPath)
    $capturePrimary = 'synthetic primary list failure'
    $captureSecondary = [System.Collections.Generic.List[string]]::new()
    try {
        $null = Write-D32Phase0BlockedDiagnostic -PrimaryError $capturePrimary -SecondaryErrors @('native cleanup incomplete') `
            -Command $diagnosticCommand -ProcessIdentity $diagnosticIdentity -RawV2Trace $incompleteTrace `
            -NativeCleanup $incompleteCleanup -StdoutPath (Join-Path $repo 'outside-owner.stdout.log') -StderrPath $null
    }
    catch { $captureSecondary.Add('blocked diagnostic capture failed: ' + $_.Exception.Message) }
    $captureFailurePreserved = $capturePrimary -ceq 'synthetic primary list failure' -and
        $captureSecondary.Count -eq 1 -and $captureSecondary[0].StartsWith('blocked diagnostic capture failed: PHASE0_DIAGNOSTIC_BLOCKED:', [StringComparison]::Ordinal) -and
        -not [IO.File]::Exists($diagnosticPath)
    Add-D32TraceIdentitySelfTestCase -Name 'diagnostic capture failure is secondary and does not replace the primary failure or manufacture a sidecar' -Passed $captureFailurePreserved

    $discoveryPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'd32-test-inventory-discovery.ps1'))
    $discoverySource = [IO.File]::ReadAllText($discoveryPath, [Text.UTF8Encoding]::new($false, $true))
    $discoveryTokens = $null; $discoveryParseErrors = $null
    $discoveryAst = [System.Management.Automation.Language.Parser]::ParseFile($discoveryPath, [ref]$discoveryTokens, [ref]$discoveryParseErrors)
    $diagnosticCatch = $discoveryAst.Find({ param($node) $node -is [System.Management.Automation.Language.CatchClauseAst] -and $node.Extent.Text.Contains('blocked diagnostic capture failed:') }, $true)
    $discoveryFailureHandlingBound = $discoveryParseErrors.Count -eq 0 -and $null -ne $diagnosticCatch -and
        $diagnosticCatch.Extent.Text.Contains('$secondaryErrors.Add(') -and
        $diagnosticCatch.Extent.Text.Contains('throw "TEST_INVENTORY_DISCOVERY_BLOCKED: $primaryError"')
    Add-D32TraceIdentitySelfTestCase -Name 'discovery outer failure path records diagnostic-write exceptions as secondary while throwing the retained primary' -Passed $discoveryFailureHandlingBound
}
finally {
    if ([IO.File]::Exists($diagnosticPath)) { [IO.File]::Delete($diagnosticPath) }
    if ([IO.File]::Exists($stdoutCapturePath)) { [IO.File]::Delete($stdoutCapturePath) }
    if ([IO.Directory]::Exists($diagnosticRoot)) { [IO.Directory]::Delete($diagnosticRoot, $false) }
    $script:D32Phase0FailureContext = $oldFailureContext
}

$cargoPath = [IO.Path]::GetFullPath('E:\d32\synthetic-cargo.exe')
$cargoWire = [ordered]@{
    name = 'cargo'
    path = $cargoPath
    sha256 = 'a' * 64
    bytes = [Int64]100
    volume_serial_hex = '0000000000000001'
    file_id_hex = '1' * 32
    reason = 'module-free test-only pinned Cargo image'
}
$cargoSnapshot = [PSCustomObject][ordered]@{
    Path = $cargoPath
    Bytes = [Int64]100
    Sha256 = 'a' * 64
    VolumeSerialHex = '0000000000000001'
    FileIdHex = '1' * 32
    Attributes = 0
    CreationTimeUtcTicks = [Int64]0
    LastWriteTimeUtcTicks = [Int64]0
}
$validatedProfile = [PSCustomObject]@{
    Profile = [PSCustomObject]@{ toolchain = [PSCustomObject]@{ cargo = [PSCustomObject]$cargoWire } }
    ExecutableInventory = @()
    WindowsImageInventory = @()
}
$baseTrace = New-D32Phase0SelfTestDebugTrace -Profile $validatedProfile -RunnerProcessId $PID -RootProcessId ($PID + 10000)

$snapshotProjection = ConvertTo-D32Phase0ExpectedRootIdentity -Identity $cargoSnapshot -ExpectedRootPath $cargoPath
$snapshotProjectionExact = $snapshotProjection.path -ceq $cargoWire.path -and $snapshotProjection.bytes -eq $cargoWire.bytes -and
    $snapshotProjection.sha256 -ceq $cargoWire.sha256 -and $snapshotProjection.volume_serial_hex -ceq $cargoWire.volume_serial_hex -and
    $snapshotProjection.file_id_hex -ceq $cargoWire.file_id_hex -and $snapshotProjection.Count -eq 5
Add-D32TraceIdentitySelfTestCase -Name 'opened-handle PascalCase snapshot projects all five caller-root fields to the exact trace wire shape' -Passed $snapshotProjectionExact
$shortSnapshot = [PSCustomObject][ordered]@{
    Path = $cargoPath; Bytes = [Int64]100; Sha256 = 'a' * 64; VolumeSerialHex = '0000000000000001'; FileIdHex = '1' * 32; Attributes = 0
}
$shortSnapshotAccepted = $false
try { $shortSnapshotAccepted = (ConvertTo-D32Phase0ExpectedRootIdentity -Identity $shortSnapshot -ExpectedRootPath $cargoPath).file_id_hex -ceq $cargoWire.file_id_hex }
catch { }
Add-D32TraceIdentitySelfTestCase -Name 'opened-handle native snapshot variant without timestamp diagnostics remains an exact accepted shape' -Passed $shortSnapshotAccepted
$wireProjection = ConvertTo-D32Phase0ExpectedRootIdentity -Identity $cargoWire -ExpectedRootPath $cargoPath
$wireProjectionExact = $wireProjection.path -ceq $cargoWire.path -and $wireProjection.bytes -eq $cargoWire.bytes -and
    $wireProjection.sha256 -ceq $cargoWire.sha256 -and $wireProjection.volume_serial_hex -ceq $cargoWire.volume_serial_hex -and
    $wireProjection.file_id_hex -ceq $cargoWire.file_id_hex -and $wireProjection.Count -eq 5
Add-D32TraceIdentitySelfTestCase -Name 'strict Profile V2 flat wire identity projects without dropping volume or file identity' -Passed $wireProjectionExact

$nativeTrace = [ordered]@{}
$topMappings = @(
    @('record_type','RecordType'), @('schema_version','SchemaVersion'), @('event_source','EventSource'), @('state','State'), @('block_reason','BlockReason'),
    @('debugger_process_id','DebuggerProcessId'), @('uncontinued_create_process_id','UncontinuedCreateProcessId'), @('uncontinued_create_continue_call_count','UncontinuedCreateContinueCallCount'),
    @('debugger_thread_id','DebuggerThreadId'), @('dedicated_debugger_thread','DedicatedDebuggerThread'), @('debugger_kill_on_exit_enabled','DebuggerKillOnExitEnabled'),
    @('root_resumed_after_kill_on_exit','RootResumedAfterKillOnExit'), @('debugger_thread_exited','DebuggerThreadExited'), @('debugger_thread_joined','DebuggerThreadJoined'),
    @('retained_process_handle_count','RetainedProcessHandleCount'), @('retained_process_handles_signaled','RetainedProcessHandlesSignaled'),
    @('debugger_association_query_verified','DebuggerAssociationQueryVerified'), @('debugger_association_absent','DebuggerAssociationAbsent'),
    @('debugger_creation_filetime','DebuggerCreationFileTime'), @('debugger_created_at_utc','DebuggerCreatedAtUtc'), @('started_at_utc','StartedAtUtc'), @('completed_at_utc','CompletedAtUtc'),
    @('debug_event_count','DebugEventCount'), @('process_create_event_count','ProcessCreateEventCount'), @('process_exit_event_count','ProcessExitEventCount'), @('process_event_count','ProcessEventCount'),
    @('thread_create_event_count','ThreadCreateEventCount'), @('thread_exit_event_count','ThreadExitEventCount'), @('image_load_event_count','ImageLoadEventCount'), @('image_unload_event_count','ImageUnloadEventCount'),
    @('exception_event_count','ExceptionEventCount'), @('debug_string_event_count','DebugStringEventCount'), @('wait_timeout_count','WaitTimeoutCount'), @('debug_api_error_count','DebugApiErrorCount'),
    @('event_chain_complete','EventChainComplete'), @('job_accounting_verified','JobAccountingVerified'), @('job_total_processes','JobTotalProcesses'), @('job_active_processes','JobActiveProcesses'),
    @('accounting_consistent','AccountingConsistent'), @('injected_interruption','InjectedInterruption')
)
foreach ($mapping in $topMappings) { $nativeTrace[$mapping[1]] = $baseTrace[$mapping[0]] }
$nativeTrace.ProcessEvents = @($baseTrace.process_events | ForEach-Object {
    [PSCustomObject][ordered]@{ Sequence = $_.sequence; Kind = $_.kind; ProcessId = $_.process_id; ParentProcessId = $_.parent_process_id; CreationFileTime = $_.creation_filetime; ParentCreationFileTime = $_.parent_creation_filetime; ExitCode = $_.exit_code }
})
$nativeTrace.Processes = @($baseTrace.processes | ForEach-Object {
    [PSCustomObject][ordered]@{ ProcessId = $_.process_id; ParentProcessId = $_.parent_process_id; CreationFileTime = $_.creation_filetime; ParentCreationFileTime = $_.parent_creation_filetime; ImagePath = $_.image_path; Bytes = $_.bytes; Sha256 = $_.sha256; VolumeSerialHex = $_.volume_serial_hex; FileIdHex = $_.file_id_hex; AllowedImageReason = $_.allowed_image_reason; ImageVerified = $_.image_verified; Exited = $_.exited; ExitCode = $_.exit_code; CreateSequence = $_.create_sequence; ExitSequence = $_.exit_sequence; CreatedAtUtc = $_.created_at_utc; ExitedAtUtc = $_.exited_at_utc }
})
$nativeWireTrace = ConvertTo-D32Phase0DebugProcessTraceDocument -Trace ([PSCustomObject]$nativeTrace)
$nativeIdentityMapped = $nativeWireTrace.processes[0].volume_serial_hex -ceq $cargoSnapshot.VolumeSerialHex -and
    $nativeWireTrace.processes[0].file_id_hex -ceq $cargoSnapshot.FileIdHex -and
    $nativeWireTrace.processes[0].sha256 -ceq $cargoSnapshot.Sha256 -and $nativeWireTrace.processes[0].bytes -eq $cargoSnapshot.Bytes
Add-D32TraceIdentitySelfTestCase -Name 'native process trace writer preserves PascalCase opened-image identity in the strict V2 wire record' -Passed $nativeIdentityMapped

$null = Test-D32Phase0DebugProcessTrace -Trace $nativeWireTrace -ExpectedRootPath $cargoPath -ExpectedRootIdentity $cargoSnapshot `
    -ExpectedParentProcessId $PID -ValidatedProfile $validatedProfile -Repository $repo
Add-D32TraceIdentitySelfTestCase -Name 'actual V2 reader accepts native snapshot after the production trace-writer and expected-pin mappings' -Passed $true

foreach ($case in @(
        [PSCustomObject]@{ Name = 'missing file ID'; Mutate = { param($value) $null = $value.Remove('file_id_hex') } },
        [PSCustomObject]@{ Name = 'extra identity field'; Mutate = { param($value) $value.unapproved_identity_alias = '1' * 32 } },
        [PSCustomObject]@{ Name = 'wrong bytes type'; Mutate = { param($value) $value.bytes = '100' } },
        [PSCustomObject]@{ Name = 'malformed volume ID'; Mutate = { param($value) $value.volume_serial_hex = 'bad' } },
        [PSCustomObject]@{ Name = 'wrongly cased alias'; Mutate = { param($value) $null = $value.Remove('volume_serial_hex'); $value.VolumeSerialHex = '0000000000000001' } }
    )) {
    $mutated = [ordered]@{}
    foreach ($key in $cargoWire.Keys) { $mutated[$key] = $cargoWire[$key] }
    & $case.Mutate $mutated
    $rejected = $false
    try { $null = ConvertTo-D32Phase0ExpectedRootIdentity -Identity $mutated -ExpectedRootPath $cargoPath }
    catch { $rejected = $_.Exception.Message -like 'PROCESS_TRACE_BLOCKED:*' }
    Add-D32TraceIdentitySelfTestCase -Name "expected identity rejects $($case.Name)" -Passed $rejected
}

foreach ($case in @(
        [PSCustomObject]@{ Name = 'missing snapshot file ID'; Mutate = { param($value) $null = $value.Remove('FileIdHex') } },
        [PSCustomObject]@{ Name = 'extra snapshot identity field'; Mutate = { param($value) $value['FileId'] = '1' * 32 } },
        [PSCustomObject]@{ Name = 'wrong snapshot attribute type'; Mutate = { param($value) $value['Attributes'] = '0' } }
    )) {
    $mutatedSnapshot = [ordered]@{
        Path = $cargoPath; Bytes = [Int64]100; Sha256 = 'a' * 64; VolumeSerialHex = '0000000000000001'; FileIdHex = '1' * 32; Attributes = 0
    }
    & $case.Mutate $mutatedSnapshot
    $rejected = $false
    try { $null = ConvertTo-D32Phase0ExpectedRootIdentity -Identity $mutatedSnapshot -ExpectedRootPath $cargoPath }
    catch { $rejected = $_.Exception.Message -like 'PROCESS_TRACE_BLOCKED:*' }
    Add-D32TraceIdentitySelfTestCase -Name "expected identity rejects $($case.Name)" -Passed $rejected
}

foreach ($fieldCase in @(
        [PSCustomObject]@{ Name = 'path'; Value = [IO.Path]::GetFullPath('E:\d32\other-cargo.exe') },
        [PSCustomObject]@{ Name = 'sha256'; Value = 'b' * 64 },
        [PSCustomObject]@{ Name = 'bytes'; Value = [Int64]101 },
        [PSCustomObject]@{ Name = 'volume_serial_hex'; Value = '0000000000000002' },
        [PSCustomObject]@{ Name = 'file_id_hex'; Value = '2' * 32 }
    )) {
    $mutatedPin = [ordered]@{}
    foreach ($key in $cargoWire.Keys) { $mutatedPin[$key] = $cargoWire[$key] }
    $mutatedPin[$fieldCase.Name] = $fieldCase.Value
    $rejected = $false
    try {
        $null = Test-D32Phase0DebugProcessTrace -Trace $nativeWireTrace -ExpectedRootPath $cargoPath -ExpectedRootIdentity $mutatedPin `
            -ExpectedParentProcessId $PID -ValidatedProfile $validatedProfile -Repository $repo
    }
    catch { $rejected = $_.Exception.Message -like 'PROCESS_TRACE_BLOCKED:*' }
    Add-D32TraceIdentitySelfTestCase -Name "actual V2 reader rejects caller root $($fieldCase.Name) tampering" -Passed $rejected
}

$wrongTraceRoot = Copy-D32TraceIdentitySelfTestShape -Value $nativeWireTrace
$wrongTraceRoot.processes[0].image_path = [IO.Path]::GetFullPath('E:\d32\unapproved-root.exe')
$wrongTraceRootRejected = $false
try { $null = Test-D32Phase0DebugProcessTrace -Trace $wrongTraceRoot -ExpectedRootPath $cargoPath -ExpectedRootIdentity $cargoSnapshot -ExpectedParentProcessId $PID -ValidatedProfile $validatedProfile -Repository $repo }
catch { $wrongTraceRootRejected = $_.Exception.Message -like 'PROCESS_TRACE_BLOCKED:*' }
Add-D32TraceIdentitySelfTestCase -Name 'actual V2 reader rejects an unexpected root image path' -Passed $wrongTraceRootRejected

$wrongRootParent = Copy-D32TraceIdentitySelfTestShape -Value $nativeWireTrace
$wrongRootParent.process_events[0].parent_process_id++
$wrongRootParentRejected = $false
try { $null = Test-D32Phase0DebugProcessTrace -Trace $wrongRootParent -ExpectedRootPath $cargoPath -ExpectedRootIdentity $cargoSnapshot -ExpectedParentProcessId $PID -ValidatedProfile $validatedProfile -Repository $repo }
catch { $wrongRootParentRejected = $_.Exception.Message -like 'PROCESS_TRACE_BLOCKED:*' }
Add-D32TraceIdentitySelfTestCase -Name 'actual V2 reader rejects root PID/creation-parent identity drift' -Passed $wrongRootParentRejected

$badCleanup = Copy-D32TraceIdentitySelfTestShape -Value $nativeWireTrace
$badCleanup.retained_process_handles_signaled = $false
$badCleanupRejected = $false
try { $null = Test-D32Phase0DebugProcessTrace -Trace $badCleanup -ExpectedRootPath $cargoPath -ExpectedRootIdentity $cargoSnapshot -ExpectedParentProcessId $PID -ValidatedProfile $validatedProfile -Repository $repo }
catch { $badCleanupRejected = $_.Exception.Message -like 'PROCESS_TRACE_BLOCKED:*' }
Add-D32TraceIdentitySelfTestCase -Name 'actual V2 reader rejects missing retained-handle cleanup evidence' -Passed $badCleanupRejected

$childPath = [IO.Path]::GetFullPath('E:\d32\synthetic-child.exe')
$childPin = [PSCustomObject]@{ Path = $childPath; Bytes = [Int64]200; Sha256 = 'b' * 64; VolumeSerialHex = '0000000000000002'; FileIdHex = '2' * 32 }
$childProfile = [PSCustomObject]@{
    Profile = $validatedProfile.Profile
    ExecutableInventory = @($childPin)
    WindowsImageInventory = @()
}
$twoProcessTrace = Copy-D32TraceIdentitySelfTestShape -Value $nativeWireTrace
$root = $twoProcessTrace.processes[0]
$rootPid = [uint32]$root.process_id
$rootCreation = [Int64]$root.creation_filetime
$childPid = [uint32]($rootPid + 1)
$childCreation = $rootCreation + 10000000L
$childExit = $childCreation + 10000000L
$rootExit = $childExit + 10000000L
$childCreatedAt = [DateTime]::FromFileTimeUtc($childCreation).ToString('o')
$childExitedAt = [DateTime]::FromFileTimeUtc($childExit).ToString('o')
$rootExitAt = [DateTime]::FromFileTimeUtc($rootExit).ToString('o')
$root.exit_sequence = 4
$root.exited_at_utc = $rootExitAt
$child = [PSCustomObject][ordered]@{
    process_id = $childPid; parent_process_id = $rootPid
    creation_filetime = $childCreation; parent_creation_filetime = $rootCreation
    image_path = $childPin.Path; bytes = $childPin.Bytes; sha256 = $childPin.Sha256
    volume_serial_hex = $childPin.VolumeSerialHex; file_id_hex = $childPin.FileIdHex
    allowed_image_reason = 'module-free-selftest-exact-child-pin'; image_verified = $true
    exited = $true; exit_code = 0; create_sequence = 2; exit_sequence = 3
    created_at_utc = $childCreatedAt; exited_at_utc = $childExitedAt
}
$twoProcessTrace.process_events = @(
    [PSCustomObject][ordered]@{ sequence = 1; kind = 'CREATE'; process_id = $rootPid; parent_process_id = [uint32]$PID; creation_filetime = $rootCreation; parent_creation_filetime = [Int64]$twoProcessTrace.debugger_creation_filetime; exit_code = 0 },
    [PSCustomObject][ordered]@{ sequence = 2; kind = 'CREATE'; process_id = $childPid; parent_process_id = $rootPid; creation_filetime = $childCreation; parent_creation_filetime = $rootCreation; exit_code = 0 },
    [PSCustomObject][ordered]@{ sequence = 3; kind = 'EXIT'; process_id = $childPid; parent_process_id = $rootPid; creation_filetime = $childCreation; parent_creation_filetime = $rootCreation; exit_code = 0 },
    [PSCustomObject][ordered]@{ sequence = 4; kind = 'EXIT'; process_id = $rootPid; parent_process_id = [uint32]$PID; creation_filetime = $rootCreation; parent_creation_filetime = [Int64]$twoProcessTrace.debugger_creation_filetime; exit_code = 0 }
)
$twoProcessTrace.processes = @($root, $child)
$twoProcessTrace.process_create_event_count = 2; $twoProcessTrace.process_exit_event_count = 2; $twoProcessTrace.process_event_count = 4
$twoProcessTrace.job_total_processes = 2; $twoProcessTrace.retained_process_handle_count = 3
$twoProcessTrace.debug_event_count = 4
$twoProcessTrace.completed_at_utc = [DateTimeOffset]::Parse($rootExitAt).AddMilliseconds(1).ToString('o')
$null = Test-D32Phase0DebugProcessTrace -Trace $twoProcessTrace -ExpectedRootPath $cargoPath -ExpectedRootIdentity $cargoSnapshot `
    -ExpectedParentProcessId $PID -ValidatedProfile $childProfile -Repository $repo
Add-D32TraceIdentitySelfTestCase -Name 'actual V2 reader accepts a pinned child with exact opened-image identity and retained parent chain' -Passed $true

$wrongChildParent = Copy-D32TraceIdentitySelfTestShape -Value $twoProcessTrace
$wrongChildParent.process_events[1].parent_process_id = $childPid + 20
$wrongChildParentRejected = $false
try { $null = Test-D32Phase0DebugProcessTrace -Trace $wrongChildParent -ExpectedRootPath $cargoPath -ExpectedRootIdentity $cargoSnapshot -ExpectedParentProcessId $PID -ValidatedProfile $childProfile -Repository $repo }
catch { $wrongChildParentRejected = $_.Exception.Message -like 'PROCESS_TRACE_BLOCKED:*' }
Add-D32TraceIdentitySelfTestCase -Name 'actual V2 reader rejects a child event with an unknown retained parent' -Passed $wrongChildParentRejected

$unknownChild = Copy-D32TraceIdentitySelfTestShape -Value $twoProcessTrace
$unknownChild.processes[1].image_path = [IO.Path]::GetFullPath('E:\d32\unapproved-child.exe')
$unknownChildRejected = $false
try { $null = Test-D32Phase0DebugProcessTrace -Trace $unknownChild -ExpectedRootPath $cargoPath -ExpectedRootIdentity $cargoSnapshot -ExpectedParentProcessId $PID -ValidatedProfile $childProfile -Repository $repo }
catch { $unknownChildRejected = $_.Exception.Message -like 'PROCESS_TRACE_BLOCKED:*' }
Add-D32TraceIdentitySelfTestCase -Name 'actual V2 reader rejects an unpinned child image instead of broadening image authority' -Passed $unknownChildRejected

$childIdentityDrift = Copy-D32TraceIdentitySelfTestShape -Value $twoProcessTrace
$childIdentityDrift.processes[1].file_id_hex = '3' * 32
$childIdentityDriftRejected = $false
try { $null = Test-D32Phase0DebugProcessTrace -Trace $childIdentityDrift -ExpectedRootPath $cargoPath -ExpectedRootIdentity $cargoSnapshot -ExpectedParentProcessId $PID -ValidatedProfile $childProfile -Repository $repo }
catch { $childIdentityDriftRejected = $_.Exception.Message -like 'PROCESS_TRACE_BLOCKED:*' }
Add-D32TraceIdentitySelfTestCase -Name 'actual V2 reader rejects a pinned child opened-file identity drift' -Passed $childIdentityDriftRejected

if ($global:D32PowerShellModuleImportAttempts -ne 0) { throw 'SELFTEST_BLOCKED: module import attempts were not zero' }
$moduleEnd = @(Microsoft.PowerShell.Core\Get-Module | ForEach-Object { '{0}|{1}|{2}' -f $_.Name, $_.Version, $_.Path } | Sort-Object)
$moduleSetUnchanged = ($moduleStart -join "`n") -ceq ($moduleEnd -join "`n")
Add-D32TraceIdentitySelfTestCase -Name 'module-free focused trace test leaves the loaded module set unchanged and import attempts at zero' -Passed $moduleSetUnchanged

$result = [ordered]@{
    record_type = 'D32_PHASE0_PROCESS_TRACE_IDENTITY_SELFTEST_V1'
    case_count = $script:cases.Count
    passed = @($script:cases | Where-Object { $_.passed }).Count
    failed = @($script:failures.ToArray())
    cases = $script:cases.ToArray()
    module_import_attempts = [int]$global:D32PowerShellModuleImportAttempts
    loaded_module_set_unchanged = $moduleSetUnchanged
    cargo_invoked = $false
    child_processes_launched = $false
    discovery_invoked = $false
    evidence_root_claimed = $false
}
[Console]::WriteLine((ConvertTo-Json -InputObject $result -Depth 12 -Compress))
if ($script:failures.Count -gt 0) { exit 1 }
