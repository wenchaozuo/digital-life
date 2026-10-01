# Module-free focused regression checks for the V2 debug-trace root identity boundary.
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath([IO.Path]::Combine($PSScriptRoot, '..'))
$phase0Path = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'd32-phase0-matrix.ps1'))
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

function Copy-D32TraceIdentitySelfTestShape {
    param([Parameter(Mandatory = $true)][object]$Value)
    return ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $Value -Depth 20 -Compress) -DateKind String
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
        [PSCustomObject]@{ Path = $profilePath; Name = 'Test-D32ProfileCanonicalPathString' },
        [PSCustomObject]@{ Path = $profilePath; Name = 'Test-D32ProfilePathEqual' },
        [PSCustomObject]@{ Path = $phase0Path; Name = 'Test-D32Phase0ExactProperties' },
        [PSCustomObject]@{ Path = $phase0Path; Name = 'Test-D32Phase0Integer' },
        [PSCustomObject]@{ Path = $phase0Path; Name = 'ConvertTo-D32Phase0ExpectedRootIdentity' },
        [PSCustomObject]@{ Path = $phase0Path; Name = 'ConvertTo-D32Phase0DebugProcessTraceDocument' },
        [PSCustomObject]@{ Path = $phase0Path; Name = 'New-D32Phase0SelfTestDebugTrace' },
        [PSCustomObject]@{ Path = $phase0Path; Name = 'Test-D32Phase0DebugProcessTrace' }
    )) {
    Set-Item -Path ('Function:script:{0}' -f $entry.Name) -Value (Import-D32TraceIdentitySelfTestFunction -Path $entry.Path -Name $entry.Name)
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
