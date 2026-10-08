# Dedicated module-free entry for current dependency-source proof only.
# The runner's SourceProofOnly parameter set has no route to Cargo, Git, the
# diagnostic admission/bootstrap path, module import, or fixture prebuild.
[CmdletBinding(DefaultParameterSetName = 'SourceProofOnly')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')][string]$Repository,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')][string]$CandidateSha,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')][string]$HistoricalOriginCandidateSha,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')][string]$ToolchainProfilePath,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')][string]$ExpectedToolchainProfileSha256,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')][string]$SourceProofAuthorityPath,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')][string]$ExpectedSourceProofAuthoritySha256,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')][string]$ExecutionAuthorityPath,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')][string]$ExpectedExecutionAuthoritySha256,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')][long]$LifecycleT0Ticks,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')][long]$LifecycleCounterFrequency,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')][long]$LifecycleWorkDeadlineTicks,
    [Parameter(Mandatory = $true, ParameterSetName = 'SourceProofOnly')][long]$LifecycleProofExpiryTicks,
    [Parameter(Mandatory = $true, ParameterSetName = 'NonSourceL1')][switch]$NonSourceL1,
    [Parameter(Mandatory = $true, ParameterSetName = 'NonSourceL1')][string]$L1AuthorityPath,
    [Parameter(Mandatory = $true, ParameterSetName = 'NonSourceL1')][string]$ExpectedL1AuthoritySha256,
    [Parameter(Mandatory = $true, ParameterSetName = 'NonSourceL1')][string]$L1CandidateSha,
    [Parameter(Mandatory = $true, ParameterSetName = 'NonSourceL1')][string]$L1BatchId,
    [Parameter(Mandatory = $true, ParameterSetName = 'NonSourceL1')][string]$L1CaseId,
    [Parameter(Mandatory = $true, ParameterSetName = 'NonSourceL1')][string]$L1Nonce,
    [Parameter(Mandatory = $true, ParameterSetName = 'NonSourceL1')][long]$L1T0Ticks,
    [Parameter(Mandatory = $true, ParameterSetName = 'NonSourceL1')][long]$L1CounterFrequency,
    [Parameter(Mandatory = $true, ParameterSetName = 'NonSourceL1')][long]$L1CaseT0Ticks,
    [Parameter(Mandatory = $true, ParameterSetName = 'NonSourceL1')][long]$L1ActiveDeadlineTicks,
    [Parameter(Mandatory = $true, ParameterSetName = 'NonSourceL1')][string]$ExpectedOuterPrelaunchBindingSha256,
    [Parameter(Mandatory = $true, ParameterSetName = 'NonSourceL1')][string]$ExpectedControllerRuntimeAdmissionSha256
)

if ($PSCmdlet.ParameterSetName -ceq 'NonSourceL1') {
    # This branch is deliberately terminal and precedes every SourceProofOnly
    # deadline check, runner reference, Profile, authority, or origin access.
    function Test-D32NonSourceL1ReaderJsonDuplicates {
        param([System.Text.Json.JsonElement]$Element)
        switch ($Element.ValueKind) {
            'Object' {
                $names = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                foreach ($property in $Element.EnumerateObject()) {
                    if (-not $names.Add($property.Name) -or (Test-D32NonSourceL1ReaderJsonDuplicates -Element $property.Value)) { return $true }
                }
            }
            'Array' { foreach ($item in $Element.EnumerateArray()) { if (Test-D32NonSourceL1ReaderJsonDuplicates -Element $item) { return $true } } }
        }
        return $false
    }
    function Test-D32NonSourceL1ReaderExactProperties {
        param([System.Text.Json.JsonElement]$Element, [string[]]$Names)
        if ($Element.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { return $false }
        $actual = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($property in $Element.EnumerateObject()) { if (-not $actual.Add($property.Name)) { return $false } }
        if ($actual.Count -ne $Names.Count) { return $false }
        foreach ($name in $Names) { if (-not $actual.Contains($name)) { return $false } }
        return $true
    }
    function Test-D32NonSourceL1ReaderString {
        param([System.Text.Json.JsonElement]$Element, [string]$Name, [string]$Expected)
        $value = $Element.GetProperty($Name)
        return ($value.ValueKind -eq [System.Text.Json.JsonValueKind]::String -and $value.GetString() -ceq $Expected)
    }
    function Test-D32NonSourceL1ReaderPositiveInteger {
        param([System.Text.Json.JsonElement]$Element, [string]$Name, [long]$Expected = 0L)
        $value = $Element.GetProperty($Name); [Int64]$number = 0
        if ($value.ValueKind -ne [System.Text.Json.JsonValueKind]::Number -or -not $value.TryGetInt64([ref]$number) -or $number -le 0) { return $false }
        return ($Expected -eq 0L -or $number -eq $Expected)
    }
    function Test-D32NonSourceL1ReaderNonnegativeInteger {
        param([System.Text.Json.JsonElement]$Element, [string]$Name, [long]$Expected)
        $value = $Element.GetProperty($Name); [Int64]$number = -1
        if ($value.ValueKind -ne [System.Text.Json.JsonValueKind]::Number -or -not $value.TryGetInt64([ref]$number) -or $number -lt 0) { return $false }
        return ($number -eq $Expected)
    }
    function Test-D32NonSourceL1ReaderFileReference {
        param([System.Text.Json.JsonElement]$Element)
        return ((Test-D32NonSourceL1ReaderExactProperties $Element @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -and
            $Element.GetProperty('path').ValueKind -eq [System.Text.Json.JsonValueKind]::String -and
            [IO.Path]::IsPathRooted($Element.GetProperty('path').GetString()) -and
            (Test-D32NonSourceL1ReaderPositiveInteger $Element 'bytes') -and
            $Element.GetProperty('sha256').ValueKind -eq [System.Text.Json.JsonValueKind]::String -and $Element.GetProperty('sha256').GetString() -cmatch '^[0-9a-f]{64}$' -and
            $Element.GetProperty('volume_serial_hex').ValueKind -eq [System.Text.Json.JsonValueKind]::String -and $Element.GetProperty('volume_serial_hex').GetString() -cmatch '^[0-9a-f]{16}$' -and
            $Element.GetProperty('file_id_hex').ValueKind -eq [System.Text.Json.JsonValueKind]::String -and $Element.GetProperty('file_id_hex').GetString() -cmatch '^[0-9a-f]{32}$')
    }
    function Test-D32NonSourceL1ReaderPathWithin {
        param([string]$Child, [string]$Parent)
        try {
            $childFull = [IO.Path]::GetFullPath($Child).TrimEnd([char[]]@([char]92, [char]47))
            $parentFull = [IO.Path]::GetFullPath($Parent).TrimEnd([char[]]@([char]92, [char]47))
            return $childFull.StartsWith($parentFull + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
        } catch { return $true }
    }
    function Test-D32NonSourceL1ReaderAuthority {
        param([System.Text.Json.JsonElement]$Authority, [string]$CaseId, [string]$Nonce,
            [string]$CandidateSha, [string]$BatchId, [string]$AuthorityPath,
            [string]$RuntimePath, [string]$OwnerId, [string]$SystemRoot)
        $authorityFields = @('schema_version', 'record_type', 'purpose', 'policy', 'gate_authority', 'candidate_sha', 'source_repo', 'repository_identity',
            'batch_id', 'run_id', 'owner_id', 'source_pins', 'powershell_runtime', 'runtime_authority', 'invocation', 'outer_caller', 'cases', 'output', 'limits', 'issued_at_utc')
        if (-not (Test-D32NonSourceL1ReaderExactProperties -Element $Authority -Names $authorityFields)) { return $false }
        if (Test-D32NonSourceL1ReaderJsonDuplicates $Authority) { return $false }
        if (-not (Test-D32NonSourceL1ReaderPositiveInteger $Authority 'schema_version' 2L)) { return $false }
        if (-not (Test-D32NonSourceL1ReaderString $Authority 'record_type' 'D32_BOUNDED_SOURCEPROOF_NON_SOURCE_L1_AUTHORITY_V2')) { return $false }
        if (-not (Test-D32NonSourceL1ReaderString $Authority 'purpose' 'NATIVE_LIFECYCLE_VALIDATION_ONLY')) { return $false }
        if (-not (Test-D32NonSourceL1ReaderString $Authority 'policy' 'D32_SOURCEPROOF_NON_SOURCE_L1_V2')) { return $false }
        if (-not (Test-D32NonSourceL1ReaderString $Authority 'gate_authority' 'NONE')) { return $false }
        if (-not (Test-D32NonSourceL1ReaderString $Authority 'candidate_sha' $CandidateSha) -or $CandidateSha -cnotmatch '^[0-9a-f]{40}$') { return $false }
        if (-not (Test-D32NonSourceL1ReaderString $Authority 'batch_id' $BatchId) -or $BatchId -cnotmatch '^[0-9a-f]{32}$') { return $false }

        $repo = $Authority.GetProperty('source_repo'); $repositoryIdentity = $Authority.GetProperty('repository_identity')
        if ($repo.ValueKind -ne [System.Text.Json.JsonValueKind]::String -or -not [IO.Path]::IsPathRooted($repo.GetString()) -or
            -not (Test-D32NonSourceL1ReaderExactProperties $repositoryIdentity @('volume_serial_hex', 'file_id_hex')) -or
            $repositoryIdentity.GetProperty('volume_serial_hex').GetString() -cnotmatch '^[0-9a-f]{16}$' -or
            $repositoryIdentity.GetProperty('file_id_hex').GetString() -cnotmatch '^[0-9a-f]{32}$') { return $false }
        $run = $Authority.GetProperty('run_id'); $owner = $Authority.GetProperty('owner_id')
        if ($run.ValueKind -ne [System.Text.Json.JsonValueKind]::String -or $run.GetString() -cnotmatch '^[0-9a-f]{32}$' -or
            $owner.ValueKind -ne [System.Text.Json.JsonValueKind]::String -or $owner.GetString() -cnotmatch '^[A-Za-z0-9._:-]{1,128}$') { return $false }
        if ([String]::IsNullOrWhiteSpace($OwnerId) -or $owner.GetString() -cne $OwnerId) { return $false }

        $repository = [IO.Path]::GetFullPath($repo.GetString())
        if ($repository -cne $repo.GetString()) { return $false }
        $expectedPins = @(
            [IO.Path]::GetFullPath([IO.Path]::Combine($repository, 'scripts/d32-bounded-diagnostic-sourceproof-controller.ps1')),
            [IO.Path]::GetFullPath([IO.Path]::Combine($repository, 'scripts/d32-bounded-diagnostic-sourceproof.ps1')),
            [IO.Path]::GetFullPath([IO.Path]::Combine($repository, 'scripts/d32-bounded-compiler-diagnostic.ps1')),
            [IO.Path]::GetFullPath([IO.Path]::Combine($repository, 'scripts/d32-bounded-compiler-diagnostic-policy.ps1')),
            [IO.Path]::GetFullPath([IO.Path]::Combine($repository, 'scripts/d32-build-toolchain-profile.ps1')),
            [IO.Path]::GetFullPath([IO.Path]::Combine($repository, 'scripts/d32-powershell-module-authority.ps1')))
        $pins = $Authority.GetProperty('source_pins')
        if ($pins.ValueKind -ne [System.Text.Json.JsonValueKind]::Array -or $pins.GetArrayLength() -ne 6) { return $false }
        for ($index = 0; $index -lt 6; $index++) {
            $pin = $pins[$index]
            if (-not (Test-D32NonSourceL1ReaderFileReference $pin) -or $pin.GetProperty('path').GetString() -cne $expectedPins[$index]) { return $false }
        }
        $runtime = $Authority.GetProperty('powershell_runtime')
        if (-not (Test-D32NonSourceL1ReaderExactProperties $runtime @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex', 'powershell_home', 'system_root')) -or
            $runtime.GetProperty('path').ValueKind -ne [System.Text.Json.JsonValueKind]::String -or
            -not [IO.Path]::IsPathRooted($runtime.GetProperty('path').GetString()) -or
            -not (Test-D32NonSourceL1ReaderPositiveInteger $runtime 'bytes') -or
            $runtime.GetProperty('sha256').ValueKind -ne [System.Text.Json.JsonValueKind]::String -or $runtime.GetProperty('sha256').GetString() -cnotmatch '^[0-9a-f]{64}$' -or
            $runtime.GetProperty('volume_serial_hex').ValueKind -ne [System.Text.Json.JsonValueKind]::String -or $runtime.GetProperty('volume_serial_hex').GetString() -cnotmatch '^[0-9a-f]{16}$' -or
            $runtime.GetProperty('file_id_hex').ValueKind -ne [System.Text.Json.JsonValueKind]::String -or $runtime.GetProperty('file_id_hex').GetString() -cnotmatch '^[0-9a-f]{32}$' -or
            $runtime.GetProperty('path').GetString() -cne $RuntimePath -or
            $runtime.GetProperty('path').GetString() -cnotmatch '^[A-Za-z]:\\Program Files\\PowerShell\\7\\pwsh\.exe$' -or
            $runtime.GetProperty('powershell_home').ValueKind -ne [System.Text.Json.JsonValueKind]::String -or
            $runtime.GetProperty('powershell_home').GetString() -cne [IO.Path]::GetDirectoryName($runtime.GetProperty('path').GetString()) -or
            $runtime.GetProperty('system_root').ValueKind -ne [System.Text.Json.JsonValueKind]::String -or
            $runtime.GetProperty('system_root').GetString() -notmatch '^[A-Za-z]:\\Windows$' -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals($runtime.GetProperty('system_root').GetString(), $SystemRoot)) { return $false }

        $output = $Authority.GetProperty('output')
        $derivedNames = @('controller_runtime_admission_path','normalreader_runtime_admission_path','forcedreader_runtime_admission_path',
            'outer_prelaunch_path','caller_outcome_path','caller_journal_path','stdout_path','stderr_path')
        if (-not (Test-D32NonSourceL1ReaderExactProperties $output (@('root_path', 'parent_path', 'root_volume_serial_hex', 'root_file_id_hex', 'parent_volume_serial_hex', 'parent_file_id_hex', 'result_path', 'journal_path') + $derivedNames))) { return $false }
        $root = $output.GetProperty('root_path').GetString(); $parent = $output.GetProperty('parent_path').GetString()
        if ($output.GetProperty('root_path').ValueKind -ne [System.Text.Json.JsonValueKind]::String -or
            $output.GetProperty('parent_path').ValueKind -ne [System.Text.Json.JsonValueKind]::String -or
            -not [IO.Path]::IsPathRooted($root) -or [IO.Path]::GetFullPath($root) -cne $root -or
            [IO.Path]::GetDirectoryName($root) -cne $parent -or
            $output.GetProperty('root_volume_serial_hex').GetString() -cnotmatch '^[0-9a-f]{16}$' -or
            $output.GetProperty('root_file_id_hex').GetString() -cnotmatch '^[0-9a-f]{32}$' -or
            $output.GetProperty('parent_volume_serial_hex').GetString() -cnotmatch '^[0-9a-f]{16}$' -or
            $output.GetProperty('parent_file_id_hex').GetString() -cnotmatch '^[0-9a-f]{32}$' -or
            $output.GetProperty('result_path').GetString() -cne [IO.Path]::Combine($root, ('D32-NSL1-' + $BatchId + '.json')) -or
            $output.GetProperty('journal_path').GetString() -cne [IO.Path]::Combine($root, ('D32-NSL1-' + $BatchId + '.jsonl')) -or
            [IO.File]::Exists($AuthorityPath) -eq $false) { return $false }
        $derivedSuffixes = @{
            controller_runtime_admission_path = 'controller-runtime.json'
            normalreader_runtime_admission_path = 'normal-reader-runtime.json'
            forcedreader_runtime_admission_path = 'forced-reader-runtime.json'
            outer_prelaunch_path = 'outer-prelaunch.json'
            caller_outcome_path = 'caller-outcome.json'
            caller_journal_path = 'caller-journal.jsonl'
            stdout_path = 'controller-stdout.log'
            stderr_path = 'controller-stderr.log'
        }
        foreach ($name in $derivedNames) {
            $value = $output.GetProperty($name)
            if ($value.ValueKind -ne [System.Text.Json.JsonValueKind]::String -or
                $value.GetString() -cne [IO.Path]::Combine($root, ('D32-NSL1-' + $BatchId + '-' + [string]$derivedSuffixes[$name]))) { return $false }
        }

        $invocation = $Authority.GetProperty('invocation')
        if (-not (Test-D32NonSourceL1ReaderExactProperties $invocation @('role', 'entry_path', 'working_directory', 'argument_policy', 'environment_policy', 'child_environment')) -or
            -not (Test-D32NonSourceL1ReaderString $invocation 'role' 'D32_SOURCEPROOF_NON_SOURCE_L1_FIXED_V2') -or
            -not (Test-D32NonSourceL1ReaderString $invocation 'entry_path' $expectedPins[1]) -or
            -not (Test-D32NonSourceL1ReaderString $invocation 'working_directory' $root) -or
            -not (Test-D32NonSourceL1ReaderString $invocation 'argument_policy' 'D32_SOURCEPROOF_NON_SOURCE_L1_FIXED_ARGV_V2') -or
            -not (Test-D32NonSourceL1ReaderString $invocation 'environment_policy' 'D32_SOURCEPROOF_NON_SOURCE_L1_FIXED_ENV_V2')) { return $false }
        $runtimeAuthority = $Authority.GetProperty('runtime_authority')
        if (-not (Test-D32NonSourceL1ReaderFileReference $runtimeAuthority) -or
            (Test-D32NonSourceL1ReaderPathWithin -Child $runtimeAuthority.GetProperty('path').GetString() -Parent $repository) -or
            (Test-D32NonSourceL1ReaderPathWithin -Child $runtimeAuthority.GetProperty('path').GetString() -Parent $root)) { return $false }
        $outerCaller = $Authority.GetProperty('outer_caller')
        if (-not (Test-D32NonSourceL1ReaderExactProperties $outerCaller @('role','entry_reference','observer_host_reference','observer_process','observer_process_policy','invocation_policy','capture_policy','ownership_policy')) -or
            -not (Test-D32NonSourceL1ReaderString $outerCaller 'role' 'D32_NON_SOURCE_L1_FIXED_OUTER_CALLER_V1') -or
            -not (Test-D32NonSourceL1ReaderFileReference $outerCaller.GetProperty('entry_reference')) -or
            $outerCaller.GetProperty('entry_reference').GetProperty('path').GetString() -cne $expectedPins[0] -or
            -not (Test-D32NonSourceL1ReaderFileReference $outerCaller.GetProperty('observer_host_reference')) -or
            $outerCaller.GetProperty('observer_host_reference').GetProperty('path').GetString() -cne $runtime.GetProperty('path').GetString()) { return $false }
        $environment = $invocation.GetProperty('child_environment')
        $environmentNames = @('SystemRoot', 'WINDIR', 'PATH', 'PSHOME', 'PSModulePath', 'PSModuleAutoLoadingPreference', 'POWERSHELL_TELEMETRY_OPTOUT',
            'DOTNET_CLI_TELEMETRY_OPTOUT', 'TEMP', 'TMP', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'HOMEDRIVE', 'HOMEPATH')
        if (-not (Test-D32NonSourceL1ReaderExactProperties $environment $environmentNames)) { return $false }
        $drive = [IO.Path]::GetPathRoot($root).TrimEnd('\'); $homePath = $root.Substring($drive.Length)
        $envExpected = @{
            SystemRoot = $runtime.GetProperty('system_root').GetString(); WINDIR = $runtime.GetProperty('system_root').GetString()
            PATH = ($runtime.GetProperty('system_root').GetString().TrimEnd('\') + '\System32;' + $runtime.GetProperty('powershell_home').GetString())
            PSHOME = $runtime.GetProperty('powershell_home').GetString(); PSModulePath = ($runtime.GetProperty('powershell_home').GetString().TrimEnd('\') + '\Modules')
            PSModuleAutoLoadingPreference = 'None'; POWERSHELL_TELEMETRY_OPTOUT = '1'; DOTNET_CLI_TELEMETRY_OPTOUT = '1'
            TEMP = $root; TMP = $root; USERPROFILE = $root; APPDATA = $root; LOCALAPPDATA = $root; HOMEDRIVE = $drive; HOMEPATH = $homePath
        }
        foreach ($name in $environmentNames) { if ($environment.GetProperty($name).ValueKind -ne [System.Text.Json.JsonValueKind]::String -or $environment.GetProperty($name).GetString() -cne [string]$envExpected[$name]) { return $false } }

        $cases = $Authority.GetProperty('cases'); $expectedIds = @('NORMAL_EXIT', 'FORCED_OWNED_TERMINATION', 'ENTRY_PIN_BINDING_REFUSAL')
        $expectedBehaviors = @('FINITE_TOKEN_EXIT_0', 'READY_THEN_FINITE_WAIT', 'DERIVED_ENTRY_SHA_MISMATCH'); $expectedCreates = @(1L, 1L, 0L)
        if ($cases.ValueKind -ne [System.Text.Json.JsonValueKind]::Array -or $cases.GetArrayLength() -ne 3) { return $false }
        $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $caseFound = $false
        for ($index = 0; $index -lt 3; $index++) {
            $case = $cases[$index]
            if (-not (Test-D32NonSourceL1ReaderExactProperties $case @('case_id', 'behavior', 'expected_create_attempts', 'nonce')) -or
                -not (Test-D32NonSourceL1ReaderString $case 'case_id' $expectedIds[$index]) -or
                -not (Test-D32NonSourceL1ReaderString $case 'behavior' $expectedBehaviors[$index]) -or
                -not (Test-D32NonSourceL1ReaderNonnegativeInteger $case 'expected_create_attempts' $expectedCreates[$index])) { return $false }
            $caseNonce = $case.GetProperty('nonce')
            if ($caseNonce.ValueKind -ne [System.Text.Json.JsonValueKind]::String -or $caseNonce.GetString() -cnotmatch '^[0-9a-f]{32}$' -or -not $seen.Add($caseNonce.GetString())) { return $false }
            if ($caseNonce.GetString() -ceq $Nonce -and $expectedIds[$index] -ceq $CaseId -and $expectedCreates[$index] -eq 1L) { $caseFound = $true }
        }
        if (-not $caseFound) { return $false }
        $limits = $Authority.GetProperty('limits')
        $limitValues = [ordered]@{ batch_milliseconds = 60000L; active_milliseconds = 5000L; cleanup_milliseconds = 10000L; audit_milliseconds = 15000L
            stdout_max_bytes = 16000L; stderr_max_bytes = 16000L; expected_output_max_bytes = 1024L; owned_buffer_max_bytes = 16777216L
            result_max_bytes = 65536L; journal_max_bytes = 65536L; max_create_process_attempts = 2L; fixed_case_count = 3L }
        if (-not (Test-D32NonSourceL1ReaderExactProperties $limits @($limitValues.Keys))) { return $false }
        foreach ($name in $limitValues.Keys) { if (-not (Test-D32NonSourceL1ReaderPositiveInteger $limits $name ([Int64]$limitValues[$name]))) { return $false } }
        $issued = $Authority.GetProperty('issued_at_utc')
        if ($issued.ValueKind -ne [System.Text.Json.JsonValueKind]::String) { return $false }
        try { $null = [DateTimeOffset]::Parse($issued.GetString(), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) } catch { return $false }
        return $true
    }
    function Get-D32NonSourceL1ReaderRefusalText {
        param([System.Exception]$Exception)
        $detail = if ($null -eq $Exception) { 'fixed L1 reader admission refused' } else { [string]$Exception.GetType().Name + ': ' + [string]$Exception.Message }
        $detail = [regex]::Replace($detail, '[\r\n\t]+', ' ')
        $detail = [regex]::Replace($detail, '(?i)["''](?:[a-z]:\\|\\\\)[^"'']*["'']', '[path]')
        $detail = [regex]::Replace($detail, '(?i)(?:[a-z]:\\|\\\\)[^\s,;)]*', '[path]')
        $detail = [regex]::Replace($detail, '(?i)\b(password|secret|token|nonce|credential|authorization)\b(?:\s*[:=]\s*|\s+)[^\s,;]+', '$1=[redacted]')
        $detail = [regex]::Replace($detail, '(?i)\b[0-9a-f]{32,64}\b', '[id]')
        $detail = [regex]::Replace($detail, '[^\x20-\x7e]', '?')
        if ($detail.Length -gt 512) { $detail = $detail.Substring(0, 512) }
        return $detail
    }
    function Write-D32NonSourceL1ReaderRuntimeFrame {
        param([Parameter(Mandatory = $true)][System.Text.Json.JsonElement]$Authority)
        $root = $Authority.GetProperty('output').GetProperty('root_path').GetString()
        $controllerPath = $Authority.GetProperty('output').GetProperty('controller_runtime_admission_path').GetString()
        if (-not (Test-D32NonSourceL1ReaderPathWithin -Child $controllerPath -Parent $root) -or
            -not [IO.File]::Exists($controllerPath) -or
            ([IO.File]::GetAttributes($controllerPath) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'fixed reader controller-admission path is absent, reparse-backed, or outside the owner-bound root'
        }
        $stream = [IO.File]::Open($controllerPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try {
            if ($stream.Length -le 0 -or $stream.Length -gt 65536) { throw 'fixed controller admission exceeds its bounded record size' }
            $bytes = [byte[]]::new([int]$stream.Length); $offset = 0
            while ($offset -lt $bytes.Length) { $read = $stream.Read($bytes,$offset,$bytes.Length-$offset); if ($read -le 0) { throw 'controller admission changed during read' }; $offset += $read }
        } finally { $stream.Dispose() }
        if ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant() -cne $ExpectedControllerRuntimeAdmissionSha256) {
            throw 'fixed reader controller-admission SHA differs from the actual bounded bytes'
        }
        $document = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false,$true).GetString($bytes))
        try {
            $controller = $document.RootElement
            $fields = @('schema_version','record_type','purpose','gate_authority','candidate_sha','batch_id','run_id','authority_reference',
                'runtime_authority_reference','outer_prelaunch_reference','parent_admission_reference','powershell_host','runner_process','startup','entry_script',
                'environment','clock','namespace_witness','module_import_order','module_closure','resolver_admission','import_verification','import_attempts','status','primary_error','secondary_errors')
            if ($controller.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
                (Test-D32NonSourceL1ReaderJsonDuplicates -Element $controller) -or
                -not (Test-D32NonSourceL1ReaderExactProperties -Element $controller -Names $fields) -or
                $controller.GetProperty('status').GetString() -cne 'ADMITTED' -or
                $controller.GetProperty('record_type').GetString() -cne 'D32_NON_SOURCE_L1_RUNTIME_ADMISSION_V1' -or
                $controller.GetProperty('runner_process').GetProperty('role').GetString() -cne 'CONTROLLER' -or
                $controller.GetProperty('candidate_sha').GetString() -cne $L1CandidateSha -or
                $controller.GetProperty('batch_id').GetString() -cne $L1BatchId -or
                $controller.GetProperty('run_id').GetString() -cne $Authority.GetProperty('run_id').GetString() -or
                $controller.GetProperty('authority_reference').GetProperty('sha256').GetString() -cne $ExpectedL1AuthoritySha256 -or
                $controller.GetProperty('outer_prelaunch_reference').GetProperty('path').GetString() -cne $Authority.GetProperty('output').GetProperty('outer_prelaunch_path').GetString()) {
                throw 'fixed controller runtime admission failed strict role/candidate/run/reference validation'
            }
            $names = @('SystemRoot','WINDIR','PATH','PSHOME','PSModulePath','PSModuleAutoLoadingPreference','POWERSHELL_TELEMETRY_OPTOUT',
                'DOTNET_CLI_TELEMETRY_OPTOUT','TEMP','TMP','USERPROFILE','APPDATA','LOCALAPPDATA','HOMEDRIVE','HOMEPATH')
            $expected = [System.Collections.Generic.List[string]]::new(); $actual = [System.Collections.Generic.List[string]]::new()
            foreach ($name in $names) {
                $expectedValue = $Authority.GetProperty('invocation').GetProperty('child_environment').GetProperty($name)
                $actualValue = [Environment]::GetEnvironmentVariable($name,[EnvironmentVariableTarget]::Process)
                if ($expectedValue.ValueKind -ne [System.Text.Json.JsonValueKind]::String -or $null -eq $actualValue) { throw 'fixed reader environment is incomplete' }
                $expected.Add($name + '=' + $expectedValue.GetString()); $actual.Add($name + '=' + $actualValue)
            }
            $expectedArray = $expected.ToArray(); [Array]::Sort($expectedArray,[StringComparer]::OrdinalIgnoreCase)
            $actualArray = $actual.ToArray(); [Array]::Sort($actualArray,[StringComparer]::OrdinalIgnoreCase)
            if ($expectedArray.Count -ne 15 -or $actualArray.Count -ne 15) { throw 'fixed reader environment count is not exactly fifteen' }
            for ($index=0; $index -lt 15; $index++) { if ($actualArray[$index] -cne $expectedArray[$index]) { throw 'actual reader environment differs from the fixed cleared block' } }
            $runtime = $Authority.GetProperty('powershell_runtime')
            $expectedModulePath = $runtime.GetProperty('powershell_home').GetString().TrimEnd('\') + '\Modules'
            if ([string]$PSModuleAutoLoadingPreference -cne 'None' -or
                [Environment]::GetEnvironmentVariable('PSModuleAutoLoadingPreference',[EnvironmentVariableTarget]::Process) -cne 'None' -or
                [Environment]::GetEnvironmentVariable('PSModulePath',[EnvironmentVariableTarget]::Process) -cne $expectedModulePath) {
                throw 'reader startup autoload/module-path policy is not the exact fixed runtime policy'
            }
            foreach ($module in $ExecutionContext.SessionState.Modules.Values) {
                if ($null -ne $module -and [string]$module.Name -cne 'Microsoft.PowerShell.Core') { throw 'actual reader module import count is not zero' }
            }
            $process = [Diagnostics.Process]::GetCurrentProcess()
            try {
                $processId = [Int64]$process.Id; $creation = [Int64]$process.StartTime.ToUniversalTime().ToFileTime()
                $image = [IO.Path]::GetFullPath([string]$process.MainModule.FileName)
                $nativePaths = [System.Collections.Generic.List[string]]::new()
                foreach ($loaded in $process.Modules) { $nativePaths.Add([IO.Path]::GetFullPath([string]$loaded.FileName)) }
            } finally { $process.Dispose() }
            $runtimePath = [IO.Path]::GetFullPath($runtime.GetProperty('path').GetString())
            if ($processId -ne [Int64]$PID -or $creation -le 0 -or
                -not [StringComparer]::OrdinalIgnoreCase.Equals($image,$runtimePath) -or $nativePaths.Count -gt 4096) {
                throw 'actual reader PID/creation/image/native-origin count is outside the fixed runtime binding'
            }
            $managedPaths = [System.Collections.Generic.List[string]]::new()
            foreach ($assembly in [AppDomain]::CurrentDomain.GetAssemblies()) {
                try { $location=[string]$assembly.Location; if (-not [string]::IsNullOrWhiteSpace($location)) { $managedPaths.Add([IO.Path]::GetFullPath($location)) } } catch { }
            }
            if ($managedPaths.Count -gt 4096) { throw 'actual reader managed-origin count exceeds the fixed bound' }
            $resolver = $controller.GetProperty('resolver_admission')
            $parentNativePaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($item in $resolver.GetProperty('native_module_paths').EnumerateArray()) { [void]$parentNativePaths.Add($item.GetString()) }
            foreach ($path in $nativePaths) { if (-not $parentNativePaths.Contains($path)) { throw 'reader loaded a native image absent from the parent admitted runtime' } }
            $parentManagedPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($item in $resolver.GetProperty('loaded_managed_assembly_paths').EnumerateArray()) { [void]$parentManagedPaths.Add($item.GetString()) }
            foreach ($path in $managedPaths) { if (-not $parentManagedPaths.Contains($path)) { throw 'reader loaded a managed assembly absent from the parent admitted runtime' } }
            $nativeOrigins = [System.Collections.Generic.List[System.Text.Json.JsonElement]]::new()
            foreach ($origin in $controller.GetProperty('import_verification').GetProperty('native_origins').EnumerateArray()) {
                if ($nativePaths.Contains($origin.GetProperty('path').GetString())) { $nativeOrigins.Add($origin.Clone()) }
            }
            if ($nativeOrigins.Count -ne $nativePaths.Count) { throw 'reader native origins do not have one exact parent-pinned content reference each' }
            $managedOrigins = [System.Collections.Generic.List[System.Text.Json.JsonElement]]::new()
            foreach ($origin in $controller.GetProperty('import_verification').GetProperty('managed_origins').EnumerateArray()) {
                if ($managedPaths.Contains($origin.GetProperty('path').GetString())) { $managedOrigins.Add($origin.Clone()) }
            }
            if ($managedOrigins.Count -ne $managedPaths.Count) { throw 'reader managed origins do not have one exact parent-pinned content reference each' }
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            try {
                $principal = [Security.Principal.WindowsPrincipal]::new($identity)
                $elevated = [bool]$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                $system = [bool]$identity.IsSystem
                $impersonating = ([Security.Principal.TokenImpersonationLevel]$identity.ImpersonationLevel -ne [Security.Principal.TokenImpersonationLevel]::None)
            } finally { $identity.Dispose() }
            $parent = $controller.GetProperty('runner_process')
            $memory = [IO.MemoryStream]::new(); $writer = [System.Text.Json.Utf8JsonWriter]::new($memory)
            try {
                $writer.WriteStartObject(); $writer.WriteNumber('process_id',$processId); $writer.WriteNumber('creation_filetime_ticks',$creation)
                $writer.WriteStartObject('image_reference'); $writer.WriteString('path',$runtime.GetProperty('path').GetString())
                $writer.WriteNumber('bytes',$runtime.GetProperty('bytes').GetInt64()); $writer.WriteString('sha256',$runtime.GetProperty('sha256').GetString())
                $writer.WriteString('volume_serial_hex',$runtime.GetProperty('volume_serial_hex').GetString()); $writer.WriteString('file_id_hex',$runtime.GetProperty('file_id_hex').GetString()); $writer.WriteEndObject()
                $writer.WriteStartObject('ordinary_token'); $writer.WriteBoolean('elevated',$elevated); $writer.WriteBoolean('high_integrity',$elevated)
                $writer.WriteBoolean('system_token',$system); $writer.WriteBoolean('thread_impersonation',$impersonating); $writer.WriteEndObject()
                $writer.WriteStartObject('parent_process'); $writer.WriteNumber('process_id',$parent.GetProperty('process_id').GetInt64())
                $writer.WriteNumber('creation_filetime_ticks',$parent.GetProperty('creation_filetime_ticks').GetInt64()); $writer.WriteEndObject()
                $writer.WriteStartArray('environment_entries'); foreach ($entry in $actualArray) { $writer.WriteStringValue($entry) }; $writer.WriteEndArray()
                $writer.WriteString('autoload','None'); $writer.WriteString('module_path',$expectedModulePath)
                $writer.WriteNumber('observed_ticks',[Diagnostics.Stopwatch]::GetTimestamp())
                $writer.WritePropertyName('namespace_witness'); $controller.GetProperty('namespace_witness').WriteTo($writer)
                $writer.WriteStartArray('module_import_order'); $writer.WriteEndArray()
                $writer.WritePropertyName('module_closure'); $controller.GetProperty('module_closure').WriteTo($writer)
                $writer.WritePropertyName('resolver_admission'); $resolver.WriteTo($writer)
                $writer.WriteStartObject('import_verification'); $writer.WriteBoolean('passed',$true)
                $writer.WriteStartArray('managed_origins'); foreach ($origin in $managedOrigins) { $origin.WriteTo($writer) }; $writer.WriteEndArray()
                $writer.WriteStartArray('native_origins'); foreach ($origin in $nativeOrigins) { $origin.WriteTo($writer) }; $writer.WriteEndArray()
                $writer.WriteNumber('utility_origin_count',0); $writer.WriteStartArray('unexpected_origins'); $writer.WriteEndArray(); $writer.WriteEndObject()
                $writer.WriteNumber('import_attempts',0); $writer.WriteEndObject(); $writer.Flush()
                $payload = [Convert]::ToBase64String($memory.ToArray())
            } finally { $writer.Dispose(); $memory.Dispose() }
        } finally { $document.Dispose() }
        [Console]::Out.WriteLine(('D32NSL1-RUNTIME|' + $payload)); [Console]::Out.Flush()
    }
    try {
        if ($PSVersionTable.PSVersion -lt [version]'7.5' -or -not [Environment]::Is64BitProcess -or
            $ExpectedL1AuthoritySha256 -cnotmatch '^[0-9a-f]{64}$' -or $L1CandidateSha -cnotmatch '^[0-9a-f]{40}$' -or
            $L1BatchId -cnotmatch '^[0-9a-f]{32}$' -or $L1Nonce -cnotmatch '^[0-9a-f]{32}$' -or
            $L1CaseId -cnotin @('NORMAL_EXIT', 'FORCED_OWNED_TERMINATION') -or
            $L1CounterFrequency -ne [Diagnostics.Stopwatch]::Frequency -or $L1T0Ticks -le 0 -or $L1CaseT0Ticks -lt $L1T0Ticks -or
            $L1ActiveDeadlineTicks -le $L1CaseT0Ticks -or [Diagnostics.Stopwatch]::GetTimestamp() -ge $L1ActiveDeadlineTicks -or
            -not [IO.Path]::IsPathRooted($L1AuthorityPath) -or [IO.Path]::GetFullPath($L1AuthorityPath) -cne $L1AuthorityPath -or
            -not [IO.File]::Exists($L1AuthorityPath) -or ([IO.File]::GetAttributes($L1AuthorityPath) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'fixed L1 input refused'
        }
        $authorityInfo = [IO.FileInfo]::new($L1AuthorityPath)
        if ($authorityInfo.Length -le 0 -or $authorityInfo.Length -gt 1048576) { throw 'fixed L1 authority byte bound refused' }
        $authorityBytes = [IO.File]::ReadAllBytes($L1AuthorityPath)
        if ($authorityBytes.Length -ne $authorityInfo.Length -or
            [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($authorityBytes)).ToLowerInvariant() -cne $ExpectedL1AuthoritySha256) {
            throw 'fixed L1 authority caller pin refused'
        }
        $authorityDocument = [System.Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false, $true).GetString($authorityBytes))
        try {
            $authority = $authorityDocument.RootElement
            $currentImagePath = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
            $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
            try { $currentOwnerId = [string]$currentIdentity.User.Value } finally { $currentIdentity.Dispose() }
            $currentSystemRoot = [Environment]::GetEnvironmentVariable('SystemRoot')
            if (-not (Test-D32NonSourceL1ReaderAuthority -Authority $authority -CaseId $L1CaseId -Nonce $L1Nonce -CandidateSha $L1CandidateSha `
                -BatchId $L1BatchId -AuthorityPath $L1AuthorityPath -RuntimePath $currentImagePath -OwnerId $currentOwnerId -SystemRoot $currentSystemRoot)) {
                throw 'fixed L1 authority binding refused'
            }
            $limits = $authority.GetProperty('limits')
            if ($limits.GetProperty('batch_milliseconds').GetInt64() -ne 60000L -or
                $limits.GetProperty('active_milliseconds').GetInt64() -ne 5000L -or
                $limits.GetProperty('cleanup_milliseconds').GetInt64() -ne 10000L -or
                $limits.GetProperty('audit_milliseconds').GetInt64() -ne 15000L -or
                $limits.GetProperty('stdout_max_bytes').GetInt64() -ne 16000L -or
                $limits.GetProperty('stderr_max_bytes').GetInt64() -ne 16000L -or
                $limits.GetProperty('expected_output_max_bytes').GetInt64() -ne 1024L -or
                $limits.GetProperty('owned_buffer_max_bytes').GetInt64() -ne 16777216L -or
                $limits.GetProperty('result_max_bytes').GetInt64() -ne 65536L -or
                $limits.GetProperty('journal_max_bytes').GetInt64() -ne 65536L) { throw 'fixed L1 authority limits refused' }
            $foundCase = $false
            foreach ($case in $authority.GetProperty('cases').EnumerateArray()) {
                if ($case.GetProperty('case_id').GetString() -ceq $L1CaseId) {
                    if ($case.GetProperty('nonce').GetString() -cne $L1Nonce -or $case.GetProperty('expected_create_attempts').GetInt64() -ne 1L) { throw 'fixed L1 nonce/count binding refused' }
                    $foundCase = $true
                }
            }
            if (-not $foundCase) { throw 'fixed L1 case binding refused' }
            $entryPins = $authority.GetProperty('source_pins')
            if ($entryPins.GetArrayLength() -ne 6 -or $entryPins[1].GetProperty('path').GetString() -cne [IO.Path]::GetFullPath($PSCommandPath)) { throw 'fixed L1 reader code binding refused' }
            $outRoot = $authority.GetProperty('output').GetProperty('root_path').GetString()
            if ($authority.GetProperty('invocation').GetProperty('working_directory').GetString() -cne $outRoot) { throw 'fixed L1 working directory binding refused' }
            $batchTicks = [Int64][Math]::Ceiling([decimal]$L1CounterFrequency * [decimal]60000 / [decimal]1000)
            $activeTicks = [Int64][Math]::Ceiling([decimal]$L1CounterFrequency * [decimal]5000 / [decimal]1000)
            if ([decimal]$L1T0Ticks + [decimal]$batchTicks -gt [decimal][Int64]::MaxValue -or
                [decimal]$L1CaseT0Ticks + [decimal]$activeTicks -gt [decimal][Int64]::MaxValue) { throw 'fixed L1 clock arithmetic overflow refused' }
            $expectedBatchDeadline = [Int64]($L1T0Ticks + $batchTicks)
            $expectedActiveDeadline = [Math]::Min([Int64]($L1CaseT0Ticks + $activeTicks), $expectedBatchDeadline)
            if ($L1ActiveDeadlineTicks -ne $expectedActiveDeadline -or $L1CaseT0Ticks -lt $L1T0Ticks -or
                [Diagnostics.Stopwatch]::GetTimestamp() -lt $L1CaseT0Ticks -or [Diagnostics.Stopwatch]::GetTimestamp() -ge $expectedActiveDeadline) {
                throw 'fixed L1 shared case/batch clock binding refused'
            }
            Write-D32NonSourceL1ReaderRuntimeFrame -Authority $authority
        } finally { $authorityDocument.Dispose() }
        if ($L1CaseId -ceq 'NORMAL_EXIT') {
            [Console]::Error.WriteLine('D32NSL1|FIXED|NORMAL')
            [Console]::Error.Flush()
            [Console]::Out.WriteLine(('D32NSL1|NORMAL_EXIT|' + $L1Nonce + '|READY'))
            [Console]::Out.Flush()
            exit 0
        }
        [Console]::Error.WriteLine('D32NSL1|FIXED|FORCED')
        [Console]::Error.Flush()
        [Console]::Out.WriteLine(('D32NSL1|FORCED_OWNED_TERMINATION|' + $L1Nonce + '|READY'))
        [Console]::Out.Flush()
        [Threading.Thread]::Sleep(4500)
        exit 0
    } catch {
        try {
            $readerErrorText = Get-D32NonSourceL1ReaderRefusalText -Exception $_.Exception
            [Console]::Error.WriteLine(('D32NSL1|REFUSED|' + $readerErrorText))
            [Console]::Error.Flush()
        } catch { }
        exit 87
    }
}

# Fail before opening any authority/profile/source pin when late startup means
# the shared proof-work window has already expired.
$lifecycleNowTicks = [Diagnostics.Stopwatch]::GetTimestamp()
if ($LifecycleT0Ticks -le 0 -or $LifecycleCounterFrequency -ne [Diagnostics.Stopwatch]::Frequency -or
    $LifecycleWorkDeadlineTicks -le $LifecycleT0Ticks -or $LifecycleProofExpiryTicks -le $LifecycleWorkDeadlineTicks -or
    $lifecycleNowTicks -lt $LifecycleT0Ticks -or $lifecycleNowTicks -ge $LifecycleWorkDeadlineTicks) {
    exit 86
}

$runnerPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'd32-bounded-compiler-diagnostic.ps1'))
& $runnerPath `
    -SourceProofOnly `
    -Repository $Repository `
    -CandidateSha $CandidateSha `
    -HistoricalOriginCandidateSha $HistoricalOriginCandidateSha `
    -ToolchainProfilePath $ToolchainProfilePath `
    -ExpectedToolchainProfileSha256 $ExpectedToolchainProfileSha256 `
    -SourceProofEntryPath $PSCommandPath `
    -SourceProofAuthorityPath $SourceProofAuthorityPath `
    -ExpectedSourceProofAuthoritySha256 $ExpectedSourceProofAuthoritySha256 `
    -ExecutionAuthorityPath $ExecutionAuthorityPath `
    -ExpectedExecutionAuthoritySha256 $ExpectedExecutionAuthoritySha256 `
    -LifecycleT0Ticks $LifecycleT0Ticks `
    -LifecycleCounterFrequency $LifecycleCounterFrequency `
    -LifecycleWorkDeadlineTicks $LifecycleWorkDeadlineTicks `
    -LifecycleProofExpiryTicks $LifecycleProofExpiryTicks
