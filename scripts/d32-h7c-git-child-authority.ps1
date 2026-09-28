# D32-only, fail-closed authority and companion-evidence helpers for the one
# direct Git-child class admitted by the approved H7-C Phase0 decision.
# Dot-source after the Phase0 profile/protoc helpers. This file never launches
# a process and never writes an external Coordinator authority.

$script:D32H7CGitAuthorityType = 'D32_PHASE0_H7C_GIT_CHILD_AUTHORITY_V1'
$script:D32H7CGitRunGrantType = 'D32_PHASE0_H7C_GIT_RUN_GRANT_V1'
$script:D32H7CGitChildAttestationType = 'D32_H7C_GIT_CHILD_ATTESTATION_V1'
$script:D32H7CGitSlotCount = 35
$script:D32H7CGitAuthorityName = 'D32-H7C-GIT-CHILD-AUTHORITY.json'
$script:D32H7CGitRunGrantName = 'D32-PHASE0-H7C-GIT-RUN-GRANT.json'
$script:D32H7CGitAttestationName = 'D32-PHASE0-H7C-GIT-CHILD-ATTESTATION.json'
$script:D32H7CGitTestInventory = @(
    'h7c_git_status_schema_is_fixed', 'h7c_model_cannot_supply_git_args', 'h7c_model_cannot_supply_executable',
    'h7c_production_schema_has_no_authority_or_process_inputs', 'h7c_real_git_executable_is_exact_bound', 'h7c_workspace_scope_required',
    'h7c_no_scope_createprocess_zero', 'h7c_no_confirmation_createprocess_zero', 'h7c_wrong_workspace_createprocess_zero',
    'h7c_root_rebind_createprocess_zero', 'h7c_same_sqlite_rev2_to_rev3_createprocess_zero', 'h7c_git_status_workspace_bytes_unchanged',
    'h7c_git_status_git_metadata_bytes_unchanged', 'h7c_git_status_creates_no_index_lock', 'h7c_git_status_spawns_no_descendant',
    'h7c_malicious_fsmonitor_helper_never_executes', 'h7c_malicious_pager_never_executes', 'h7c_gitfile_outside_workspace_is_rejected',
    'h7c_core_worktree_outside_scope_is_rejected', 'h7c_include_path_outside_scope_is_rejected', 'h7c_include_if_path_outside_scope_is_rejected',
    'h7c_local_config_rejects_r2_external_authority_keys', 'h7c_worktree_config_outside_scope_is_rejected_before_process_creation',
    'h7c_worktree_config_include_outside_scope_is_rejected_before_process_creation', 'h7c_core_excludes_file_outside_scope_is_rejected',
    'h7c_core_attributes_file_outside_scope_is_rejected', 'h7c_filter_clean_real_subsection_is_rejected', 'h7c_filter_process_real_subsection_is_rejected',
    'h7c_filter_legacy_dotted_subsection_is_rejected', 'h7c_large_workspace_is_not_part_of_metadata_fence',
    'h7c_large_git_object_area_is_not_part_of_metadata_fence', 'h7c_large_git_object_area_profile_admission_succeeds',
    'h7c_alternates_redirect_profile_admission_is_rejected', 'h7c_post_confirmation_config_toctou_createprocess_zero',
    'h7c_post_confirmation_git_metadata_toctou_createprocess_zero', 'h7c_post_confirmation_alternates_redirect_createprocess_zero',
    'h7c_status_parser_rejects_absolute_path', 'h7c_status_parser_rejects_parent_escape', 'h7c_status_parser_is_bounded',
    'h7c_model_output_has_no_absolute_paths', 'h7c_uses_global_h7_admission', 'h7c_global_quarantine_blocks_git_before_confirmation',
    'h7c_outer_abort_preserves_h7_cleanup', 'real_codex_h7c_git_status_canary', 'real_codex_h7c_without_scope_createprocess_zero',
    'real_codex_h7c_output_exposes_no_authority_facts'
)

function Get-D32H7CGitFixedArgv {
    return [ordered]@{
        setup = @(
            @('init', '--quiet'),
            @('config', 'user.name', 'D29-H7-C'),
            @('config', 'user.email', 'd29h7c@example.invalid'),
            @('add', '--', 'unchanged.txt', 'modified.txt'),
            @('commit', '--quiet', '-m', 'initial')
        )
        status = @('--no-pager', '--no-optional-locks', '-c', 'core.fsmonitor=false', '-c', 'core.untrackedCache=false', '-c', 'submodule.recurse=false', 'status', '--porcelain=v1', '-z', '--untracked-files=all', '--ignore-submodules=all')
    }
}

function Get-D32H7CGitPolicyDocument {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$CandidateSha,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][object]$GitImage,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )
    $cargo = [string]$ValidatedProfile.Profile.toolchain.cargo.path
    $suiteArgs = @(Get-D32Phase0TestCommand -Package 'vita' -Kind 'suite')
    $argv = Get-D32H7CGitFixedArgv
    return [ordered]@{
        policy_version = 1
        suite = [ordered]@{
            name = 'vita-full-local-suite'
            package = 'vita'
            executable = $cargo
            arguments = $suiteArgs
            command_line = ConvertTo-D32Phase0CommandLine -Arguments (@($cargo) + $suiteArgs)
            working_directory = [IO.Path]::GetFullPath($Repository)
            timeout_seconds = $TimeoutSeconds
            environment = [ordered]@{ D32_EXPECTED_CANDIDATE_SHA = $CandidateSha }
        }
        git_image = [ordered]@{
            path = [string]$GitImage.Path
            bytes = [Int64]$GitImage.Bytes
            sha256 = [string]$GitImage.Sha256
            volume_serial_hex = [string]$GitImage.VolumeSerialHex
            file_id_hex = [string]$GitImage.FileIdHex
        }
        parent_policy = 'one direct pinned Cargo-root child test executable under candidate vita-agent target; Git is direct child of that test executable in the same verified nonbreakaway Job'
        job_policy = 'existing unique owned Job; kill-on-close; breakaway flags absent; each admitted Git CREATE remains in this Job'
        process_test_attribution = 'NONE'
        slot_count = $script:D32H7CGitSlotCount
        slot_layout = 'r\t\d32-h7c-slot-{01..35}\repo and sibling git-home; each leaf fresh, canonical, regular, owner-bound'
        git_fixed_argv = $argv
        command_limits = [ordered]@{ init_per_slot = 1; user_name_config_per_slot = 1; user_email_config_per_slot = 1; add_per_slot = 1; commit_per_slot = 1; status_per_slot = 1; setup_per_slot = 5; total_git_children_max = 210 }
        setup_environment = [ordered]@{
            required_keys = @('GCM_INTERACTIVE', 'GIT_CEILING_DIRECTORIES', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_NOSYSTEM', 'GIT_CONFIG_SYSTEM', 'GIT_NO_REPLACE_OBJECTS', 'GIT_OPTIONAL_LOCKS', 'GIT_PAGER', 'GIT_TERMINAL_PROMPT', 'HOME', 'TEMP', 'TMP', 'USERPROFILE', 'WINDIR', 'SystemRoot', 'XDG_CONFIG_HOME')
            system_root_rule = 'SystemRoot and WINDIR both equal the host GetWindowsDirectoryW canonical root'
            temp_rule = 'TEMP and TMP both equal the owner-bound Phase0 r\\t TempRoot'
            home_rule = 'HOME, USERPROFILE, and XDG_CONFIG_HOME all equal this slot git-home directory'
            git_config_rule = 'GIT_CONFIG_NOSYSTEM=1; GIT_CONFIG_SYSTEM and GIT_CONFIG_GLOBAL both equal this slot git-home\\empty.gitconfig'
            fixed_values = [ordered]@{ GCM_INTERACTIVE = 'Never'; GIT_NO_REPLACE_OBJECTS = '1'; GIT_OPTIONAL_LOCKS = '0'; GIT_PAGER = 'cat'; GIT_TERMINAL_PROMPT = '0' }
        }
        status_environment = [ordered]@{
            required_keys = @('COMSPEC', 'GCM_INTERACTIVE', 'GIT_CEILING_DIRECTORIES', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_NOSYSTEM', 'GIT_OPTIONAL_LOCKS', 'GIT_TERMINAL_PROMPT', 'HOME', 'SystemDrive', 'SystemRoot', 'windir')
            git_config_rule = 'GIT_CONFIG_NOSYSTEM=1; GIT_CONFIG_GLOBAL equals this slot git-home\\empty.gitconfig'
            fixed_values = [ordered]@{ GCM_INTERACTIVE = 'Never'; GIT_OPTIONAL_LOCKS = '0'; GIT_TERMINAL_PROMPT = '0' }
        }
        native_environment = [ordered]@{
            required_keys = @('COMSPEC', 'SystemDrive', 'SystemRoot', 'windir')
            rule = 'only Windows CreateProcess OS plumbing: host-root SystemRoot/windir, SystemDrive, and canonical OS ComSpec string; these do not authorize process creation'
        }
        forbidden_environment = @('PATH', 'GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_CONFIG_COUNT', 'GIT_CONFIG_PARAMETERS', 'GIT_CONFIG_NOSYSTEM=false', 'GIT_ASKPASS', 'SSH_ASKPASS', 'GIT_SSH', 'GIT_SSH_COMMAND', 'GCM_INTERACTIVE_PROMPT', 'GIT_CONFIG_KEY_*', 'GIT_CONFIG_VALUE_*')
    }
}

function Get-D32H7CGitPolicyDigest {
    param([Parameter(Mandatory = $true)][object]$Policy)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $Policy -Depth 16 -Compress))
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

function Get-D32H7CGitAuthorityTemplate {
    param([Parameter(Mandatory = $true)][string]$Repository, [Parameter(Mandatory = $true)][string]$CandidateSha,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile, [Parameter(Mandatory = $true)][string]$EvidenceRoot,
        [Parameter(Mandatory = $true)][string]$TempRoot, [Parameter(Mandatory = $true)][object]$GitImage,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds)
    if ($CandidateSha -cnotmatch '^[0-9a-f]{40}$' -or $TimeoutSeconds -lt 60 -or $TimeoutSeconds -gt 14400 -or
        -not (Test-D32ProfilePathEqual -Left $TempRoot -Right (Join-Path (Join-Path $EvidenceRoot 'r') 't'))) { throw 'H7C_GIT_AUTHORITY_BLOCKED: candidate/timeout/fresh TempRoot for authority template is invalid' }
    $profileRef = [ordered]@{ path = [string]$ValidatedProfile.ProfilePath; sha256 = [string]$ValidatedProfile.Digest; bytes = [Int64]$ValidatedProfile.Identity.Bytes; volume_serial_hex = [string]$ValidatedProfile.Identity.VolumeSerialHex; file_id_hex = [string]$ValidatedProfile.Identity.FileIdHex }
    $policy = Get-D32H7CGitPolicyDocument -Repository $Repository -CandidateSha $CandidateSha -ValidatedProfile $ValidatedProfile -GitImage $GitImage -TimeoutSeconds $TimeoutSeconds
    return [ordered]@{
        schema_version = 1; record_type = $script:D32H7CGitAuthorityType; scope = 'D32_PHASE0_VITA_FULL_LOCAL_SUITE_ONLY'
        candidate_sha = $CandidateSha; toolchain_profile = $profileRef
        evidence_root_path = [IO.Path]::GetFullPath($EvidenceRoot); temp_root_path = [IO.Path]::GetFullPath($TempRoot)
        git_image = [ordered]@{ path = [string]$GitImage.Path; bytes = [Int64]$GitImage.Bytes; sha256 = [string]$GitImage.Sha256; volume_serial_hex = [string]$GitImage.VolumeSerialHex; file_id_hex = [string]$GitImage.FileIdHex }
        fixed_suite = [ordered]@{ name = [string]$policy.suite.name; package = [string]$policy.suite.package; executable = [string]$policy.suite.executable; arguments = @($policy.suite.arguments); command_line = [string]$policy.suite.command_line; working_directory = [string]$policy.suite.working_directory; timeout_seconds = [int]$policy.suite.timeout_seconds; policy = $policy }
        policy_sha256 = Get-D32H7CGitPolicyDigest -Policy $policy
    }
}

function Get-D32H7CGitNativePolicyText {
    param([Parameter(Mandatory = $true)][object]$RunGrant, [Parameter(Mandatory = $true)][string]$Repository, [Parameter(Mandatory = $true)][object]$GitImage)
    $lines = [System.Collections.Generic.List[string]]::new()
    $root = $RunGrant.Document.evidence_root
    $temp = $RunGrant.Document.temp_root
    $owner = $RunGrant.Document.owner_marker
    $lines.Add((@('D32_H7C_NATIVE_POLICY_V1', [IO.Path]::GetFullPath($Repository), [string]$RunGrant.Document.fixed_suite.executable,
        [string]$root.path, [string]$root.volume_serial_hex, [string]$root.file_id_hex,
        [string]$temp.path, [string]$temp.volume_serial_hex, [string]$temp.file_id_hex,
        [string]$owner.path, [string]$owner.bytes, [string]$owner.sha256, [string]$owner.volume_serial_hex, [string]$owner.file_id_hex,
        [string]$GitImage.Path, [string]$GitImage.Bytes, [string]$GitImage.Sha256, [string]$GitImage.VolumeSerialHex, [string]$GitImage.FileIdHex) -join "`t"))
    foreach ($slot in @($RunGrant.Document.slots)) {
        $lines.Add((@('SLOT', [string]$slot.slot, [string]$slot.path.path, [string]$slot.path.volume_serial_hex, [string]$slot.path.file_id_hex,
            [string]$slot.repo.path, [string]$slot.repo.volume_serial_hex, [string]$slot.repo.file_id_hex,
            [string]$slot.git_home.path, [string]$slot.git_home.volume_serial_hex, [string]$slot.git_home.file_id_hex,
            [string]$slot.empty_git_config.path, [string]$slot.empty_git_config.volume_serial_hex, [string]$slot.empty_git_config.file_id_hex) -join "`t"))
    }
    return $lines -join "`n"
}


function Get-D32H7CGitExternalFileReference {
    param([Parameter(Mandatory = $true)][string]$Path)
    $snapshot = Get-D32ProfileFileSnapshot -Path $Path
    return [ordered]@{ path = $snapshot.Path; bytes = [Int64]$snapshot.Bytes; sha256 = [string]$snapshot.Sha256; volume_serial_hex = [string]$snapshot.VolumeSerialHex; file_id_hex = [string]$snapshot.FileIdHex }
}

function Assert-D32H7CGitFileReferenceIdentity {
    param([Parameter(Mandatory = $true)][object]$Reference, [Parameter(Mandatory = $true)][object]$Snapshot, [Parameter(Mandatory = $true)][string]$Name)
    if (-not (Test-D32Phase0ExactProperties -Object $Reference -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -or
        $Reference.path -isnot [string] -or -not (Test-D32ProfilePathEqual -Left $Reference.path -Right $Snapshot.Path) -or
        -not (Test-D32Phase0Integer -Value $Reference.bytes -Positive) -or [Int64]$Reference.bytes -ne [Int64]$Snapshot.Bytes -or
        $Reference.sha256 -isnot [string] -or $Reference.sha256 -cne [string]$Snapshot.Sha256 -or
        $Reference.volume_serial_hex -isnot [string] -or $Reference.volume_serial_hex -cne [string]$Snapshot.VolumeSerialHex -or
        $Reference.file_id_hex -isnot [string] -or $Reference.file_id_hex -cne [string]$Snapshot.FileIdHex) {
        throw "H7C_GIT_ATTESTATION_BLOCKED: $Name bytes or opened-handle identity differ from its strict reference"
    }
    return $true
}

function Write-D32H7CGitJsonCreateNew {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][object]$Document)
    $full = [IO.Path]::GetFullPath($Path)
    if (-not (Test-D32ProfileCanonicalPathString -Path $full) -or -not (Test-D32ProfileNoReparsePath -Path $full -AllowMissingLeaf)) { throw 'H7C_GIT_AUTHORITY_BLOCKED: create-new evidence path is noncanonical or reparse-backed' }
    $parent = [IO.Path]::GetDirectoryName($full)
    if (-not (Test-D32ProfileNoReparsePath -Path $parent)) { throw 'H7C_GIT_AUTHORITY_BLOCKED: create-new evidence parent is missing or reparse-backed' }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $Document -Depth 32 -Compress) + [Environment]::NewLine)
    $stream = [IO.File]::Open($full, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    return Get-D32H7CGitExternalFileReference -Path $full
}

function Read-D32H7CGitJsonFile {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$ExpectedSha256)
    if ($ExpectedSha256 -cnotmatch '^[0-9a-f]{64}$' -or -not (Test-D32ProfileCanonicalPathString -Path $Path) -or -not (Test-D32ProfileNoReparsePath -Path $Path)) { throw 'H7C_GIT_AUTHORITY_BLOCKED: external evidence path/hash is malformed' }
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $before = Get-D32ProfileFileSnapshot -Path $Path
        if ($before.Sha256 -cne $ExpectedSha256) { throw 'H7C_GIT_AUTHORITY_BLOCKED: evidence bytes do not match the caller-pinned SHA-256' }
        $stream.Position = 0
        $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::UTF8, $true, 4096, $true)
        try { $raw = $reader.ReadToEnd() } finally { $reader.Dispose() }
        $after = Get-D32ProfileFileSnapshot -Path $Path
        if ($before.Bytes -ne $after.Bytes -or $before.Sha256 -cne $after.Sha256 -or $before.VolumeSerialHex -cne $after.VolumeSerialHex -or $before.FileIdHex -cne $after.FileIdHex) { throw 'H7C_GIT_AUTHORITY_BLOCKED: evidence changed during read' }
    }
    finally { $stream.Dispose() }
    if (Test-D32Phase0JsonDuplicateKeys -Json $raw) { throw 'H7C_GIT_AUTHORITY_BLOCKED: duplicate-key or invalid JSON' }
    return [PSCustomObject]@{ Document = ($raw | ConvertFrom-D32Phase0Json); Snapshot = $before; Raw = $raw }
}

function Get-D32H7CGitChildAttestationInputs {
    param([Parameter(Mandatory = $true)][object]$Reference, [Parameter(Mandatory = $true)][string]$EvidenceRoot)
    if (-not (Test-D32Phase0ExactProperties -Object $Reference -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -or
        -not (Test-D32ProfilePathEqual -Left $Reference.path -Right (Join-Path $EvidenceRoot $script:D32H7CGitAttestationName))) { throw 'H7C_GIT_ATTESTATION_BLOCKED: companion file reference is not fixed under the Phase0 EvidenceRoot' }
    $read = Read-D32H7CGitJsonFile -Path ([string]$Reference.path) -ExpectedSha256 ([string]$Reference.sha256)
    $null = Assert-D32H7CGitFileReferenceIdentity -Reference $Reference -Snapshot $read.Snapshot -Name 'H7-C child attestation'
    $doc = $read.Document
    if (-not (Test-D32Phase0ExactProperties -Object $doc -Expected @('schema_version', 'record_type', 'status', 'candidate_sha', 'toolchain_profile', 'authority', 'run_grant', 'owner_marker', 'run_id', 'evidence_root', 'temp_root', 'git_image', 'fixed_suite', 'test_attribution', 'test_inventory', 'git_child_count', 'git_children', 'policy_sha256', 'generated_at_utc')) -or
        $doc.schema_version -ne 1 -or $doc.record_type -cne $script:D32H7CGitChildAttestationType -or $doc.status -cne 'PASS' -or
        -not (Test-D32Phase0ExactProperties -Object $doc.authority -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -or
        -not (Test-D32Phase0ExactProperties -Object $doc.run_grant -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -or
        -not (Test-D32Phase0ExactProperties -Object $doc.fixed_suite -Expected @('name', 'executable', 'executable_sha256', 'executable_bytes', 'executable_volume_serial_hex', 'executable_file_id_hex', 'arguments', 'command_line', 'working_directory', 'timeout_seconds', 'candidate_sha_environment', 'exit_code', 'stdout', 'stderr', 'process_trace_sha256')) -or
        -not (Test-D32Phase0ExactProperties -Object $doc.fixed_suite.candidate_sha_environment -Expected @('name', 'value')) -or
        $doc.fixed_suite.candidate_sha_environment.name -cne 'D32_EXPECTED_CANDIDATE_SHA' -or
        $doc.fixed_suite.candidate_sha_environment.value -cne $doc.candidate_sha -or
        -not (Test-D32Phase0Integer -Value $doc.fixed_suite.timeout_seconds -Positive) -or
        -not (Test-D32Phase0ExactProperties -Object $doc.git_image -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex'))) { throw 'H7C_GIT_ATTESTATION_BLOCKED: companion prevalidation header schema is malformed' }
    return [PSCustomObject]@{ Document = $doc; AuthorityReference = $doc.authority; GitImage = [PSCustomObject]@{
        Path = [string]$doc.git_image.path; Bytes = [Int64]$doc.git_image.bytes; Sha256 = [string]$doc.git_image.sha256
        VolumeSerialHex = [string]$doc.git_image.volume_serial_hex; FileIdHex = [string]$doc.git_image.file_id_hex
    }; TimeoutSeconds = [int]$doc.fixed_suite.timeout_seconds }
}

function Test-D32H7CGitAuthority {
    param(
        [Parameter(Mandatory = $true)][string]$AuthorityPath,
        [Parameter(Mandatory = $true)][string]$ExpectedAuthoritySha256,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$CandidateSha,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][string]$EvidenceRoot,
        [Parameter(Mandatory = $true)][string]$TempRoot,
        [Parameter(Mandatory = $true)][object]$GitImage,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )
    if ((Test-D32ProfilePathWithin -Child $AuthorityPath -Parent $Repository) -or (Test-D32ProfilePathWithin -Child $AuthorityPath -Parent $EvidenceRoot)) { throw 'H7C_GIT_AUTHORITY_BLOCKED: coordinator authority must be external to candidate and run EvidenceRoot' }
    $read = Read-D32H7CGitJsonFile -Path $AuthorityPath -ExpectedSha256 $ExpectedAuthoritySha256
    $doc = $read.Document
    $fields = @('schema_version', 'record_type', 'scope', 'candidate_sha', 'toolchain_profile', 'evidence_root_path', 'temp_root_path', 'git_image', 'fixed_suite', 'policy_sha256')
    if (-not (Test-D32Phase0ExactProperties -Object $doc -Expected $fields) -or
        -not (Test-D32Phase0Integer -Value $doc.schema_version) -or [Int64]$doc.schema_version -ne 1 -or
        $doc.record_type -cne $script:D32H7CGitAuthorityType -or $doc.scope -cne 'D32_PHASE0_VITA_FULL_LOCAL_SUITE_ONLY' -or
        $doc.candidate_sha -cne $CandidateSha -or
        -not (Test-D32Phase0ExactProperties -Object $doc.toolchain_profile -Expected @('path', 'sha256', 'bytes', 'volume_serial_hex', 'file_id_hex')) -or
        -not (Test-D32ProfilePathEqual -Left $doc.toolchain_profile.path -Right $ValidatedProfile.ProfilePath) -or
        $doc.toolchain_profile.sha256 -cne $ValidatedProfile.Digest -or [Int64]$doc.toolchain_profile.bytes -ne [Int64]$ValidatedProfile.Identity.Bytes -or
        $doc.toolchain_profile.volume_serial_hex -cne $ValidatedProfile.Identity.VolumeSerialHex -or $doc.toolchain_profile.file_id_hex -cne $ValidatedProfile.Identity.FileIdHex -or
        -not (Test-D32ProfilePathEqual -Left $doc.evidence_root_path -Right $EvidenceRoot) -or
        -not (Test-D32ProfilePathEqual -Left $doc.temp_root_path -Right $TempRoot)) { throw 'H7C_GIT_AUTHORITY_BLOCKED: strict authority schema/candidate/profile/fresh path binding differs' }
    if (-not (Test-D32Phase0ExactProperties -Object $doc.git_image -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -or
        -not (Test-D32ProfilePathEqual -Left $doc.git_image.path -Right $GitImage.Path) -or
        [Int64]$doc.git_image.bytes -ne [Int64]$GitImage.Bytes -or $doc.git_image.sha256 -cne $GitImage.Sha256 -or
        $doc.git_image.volume_serial_hex -cne $GitImage.VolumeSerialHex -or $doc.git_image.file_id_hex -cne $GitImage.FileIdHex) { throw 'H7C_GIT_AUTHORITY_BLOCKED: exact caller-pinned direct Git image identity differs' }
    $expectedAuthority = Get-D32H7CGitAuthorityTemplate -Repository $Repository -CandidateSha $CandidateSha -ValidatedProfile $ValidatedProfile -EvidenceRoot $EvidenceRoot -TempRoot $TempRoot -GitImage $GitImage -TimeoutSeconds $TimeoutSeconds
    $expectedPolicy = $expectedAuthority.fixed_suite.policy
    if (-not (Test-D32Phase0ExactProperties -Object $doc.fixed_suite -Expected @('name', 'package', 'executable', 'arguments', 'command_line', 'working_directory', 'timeout_seconds', 'policy')) -or
        $doc.fixed_suite.name -cne $expectedPolicy.suite.name -or $doc.fixed_suite.package -cne $expectedPolicy.suite.package -or
        -not (Test-D32ProfilePathEqual -Left $doc.fixed_suite.executable -Right $expectedPolicy.suite.executable) -or
        ($doc.fixed_suite.arguments -join "`0") -cne ($expectedPolicy.suite.arguments -join "`0") -or
        $doc.fixed_suite.command_line -cne $expectedPolicy.suite.command_line -or
        -not (Test-D32ProfilePathEqual -Left $doc.fixed_suite.working_directory -Right $expectedPolicy.suite.working_directory) -or
        [Int64]$doc.fixed_suite.timeout_seconds -ne $TimeoutSeconds -or
        (ConvertTo-Json -InputObject $doc.fixed_suite.policy -Depth 16 -Compress) -cne (ConvertTo-Json -InputObject $expectedPolicy -Depth 16 -Compress) -or
        $doc.policy_sha256 -cne (Get-D32H7CGitPolicyDigest -Policy $expectedPolicy)) { throw 'H7C_GIT_AUTHORITY_BLOCKED: fixed suite argv, timeout, finite Git operations, slot, environment, parent-chain, or Job policy digest differs' }
    return [PSCustomObject]@{ Document = $doc; Reference = Get-D32H7CGitExternalFileReference -Path $AuthorityPath; Policy = $expectedPolicy; PolicySha256 = [string]$doc.policy_sha256 }
}

function New-D32H7CGitRunGrant {
    param(
        [Parameter(Mandatory = $true)][object]$Authority,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$CandidateSha,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][string]$EvidenceRoot,
        [Parameter(Mandatory = $true)][string]$TempRoot,
        [Parameter(Mandatory = $true)][string]$RunId,
        [Parameter(Mandatory = $true)][object]$OwnerMarker,
        [Parameter(Mandatory = $true)][object]$GitImage
    )
    if ($RunId -cnotmatch '^[0-9a-f]{32}$' -or -not (Test-D32ProfilePathEqual -Left $TempRoot -Right (Join-Path (Join-Path $EvidenceRoot 'r') 't')) -or
        -not (Test-D32ProfileNoReparsePath -Path $TempRoot)) { throw 'H7C_GIT_GRANT_BLOCKED: owner/run/temp root binding is invalid' }
    $revalidatedAuthority = Test-D32H7CGitAuthority -AuthorityPath ([string]$Authority.Reference.path) `
        -ExpectedAuthoritySha256 ([string]$Authority.Reference.sha256) -Repository $Repository -CandidateSha $CandidateSha `
        -ValidatedProfile $ValidatedProfile -EvidenceRoot $EvidenceRoot -TempRoot $TempRoot -GitImage $GitImage `
        -TimeoutSeconds ([int]$Authority.Document.fixed_suite.timeout_seconds)
    if ((ConvertTo-Json -InputObject $revalidatedAuthority.Reference -Depth 6 -Compress) -cne
        (ConvertTo-Json -InputObject $Authority.Reference -Depth 6 -Compress)) { throw 'H7C_GIT_GRANT_BLOCKED: coordinator authority reference changed before per-run grant creation' }
    $slots = [System.Collections.Generic.List[object]]::new()
    for ($index = 1; $index -le $script:D32H7CGitSlotCount; $index++) {
        $slotName = 'd32-h7c-slot-{0:D2}' -f $index
        $slotPath = Join-Path $TempRoot $slotName
        if (Test-D32Phase0DirectoryEntryExists -Path $slotPath) { throw "H7C_GIT_GRANT_BLOCKED: stale or colliding slot already exists: $slotPath" }
        $slotIdentity = New-D32ProfileDirectoryCreateNew -Path $slotPath
        $repoPath = Join-Path $slotPath 'repo'
        $homePath = Join-Path $slotPath 'git-home'
        $repoIdentity = New-D32ProfileDirectoryCreateNew -Path $repoPath
        $homeIdentity = New-D32ProfileDirectoryCreateNew -Path $homePath
        foreach ($path in @($slotPath, $repoPath, $homePath)) {
            if (-not (Test-D32ProfileCanonicalPathString -Path $path) -or -not (Test-D32ProfileNoReparsePath -Path $path)) { throw "H7C_GIT_GRANT_BLOCKED: slot directory is not a canonical regular directory: $path" }
        }
        $emptyConfig = Join-Path $homePath 'empty.gitconfig'
        $configStream = [IO.File]::Open($emptyConfig, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        try { $configStream.Flush($true) } finally { $configStream.Dispose() }
        $configRef = Get-D32H7CGitExternalFileReference -Path $emptyConfig
        if ([Int64]$configRef.bytes -ne 0 -or $configRef.sha256 -cne 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') { throw 'H7C_GIT_GRANT_BLOCKED: git-home global/system config is not a fresh empty regular file' }
        $slotIdentity = Get-D32ProfileDirectoryIdentity -Path $slotPath
        $repoIdentity = Get-D32ProfileDirectoryIdentity -Path $repoPath
        $homeIdentity = Get-D32ProfileDirectoryIdentity -Path $homePath
        $slots.Add([ordered]@{
            slot = $slotName
            path = [ordered]@{ path = [string]$slotIdentity.Path; volume_serial_hex = [string]$slotIdentity.VolumeSerialHex; file_id_hex = [string]$slotIdentity.FileIdHex }
            repo = [ordered]@{ path = [string]$repoIdentity.Path; volume_serial_hex = [string]$repoIdentity.VolumeSerialHex; file_id_hex = [string]$repoIdentity.FileIdHex }
            git_home = [ordered]@{ path = [string]$homeIdentity.Path; volume_serial_hex = [string]$homeIdentity.VolumeSerialHex; file_id_hex = [string]$homeIdentity.FileIdHex }
            empty_git_config = $configRef
        })
    }
    $rootIdentity = Get-D32ProfileDirectoryIdentity -Path $EvidenceRoot
    $tempIdentity = Get-D32ProfileDirectoryIdentity -Path $TempRoot
    $doc = [ordered]@{
        schema_version = 1
        record_type = $script:D32H7CGitRunGrantType
        status = 'BOUND'
        authority = $Authority.Reference
        policy_sha256 = $Authority.PolicySha256
        candidate_sha = $CandidateSha
        toolchain_profile = [ordered]@{ path = $ValidatedProfile.ProfilePath; sha256 = $ValidatedProfile.Digest; bytes = [Int64]$ValidatedProfile.Identity.Bytes; volume_serial_hex = $ValidatedProfile.Identity.VolumeSerialHex; file_id_hex = $ValidatedProfile.Identity.FileIdHex }
        owner_marker = $OwnerMarker
        run_id = $RunId
        evidence_root = [ordered]@{ path = $EvidenceRoot; volume_serial_hex = $rootIdentity.VolumeSerialHex; file_id_hex = $rootIdentity.FileIdHex }
        temp_root = [ordered]@{ path = $TempRoot; volume_serial_hex = $tempIdentity.VolumeSerialHex; file_id_hex = $tempIdentity.FileIdHex }
        git_image = [ordered]@{ path = $GitImage.Path; bytes = [Int64]$GitImage.Bytes; sha256 = $GitImage.Sha256; volume_serial_hex = $GitImage.VolumeSerialHex; file_id_hex = $GitImage.FileIdHex }
        fixed_suite = $Authority.Document.fixed_suite
        slots = @($slots.ToArray())
        parent_policy = [string]$Authority.Policy.parent_policy
        job_policy = [string]$Authority.Policy.job_policy
        process_test_attribution = 'NONE'
        test_inventory = $script:D32H7CGitTestInventory
        test_result_policy = 'Every fixed H7-C libtest inventory item must appear exactly once in the full Vita suite log with result ok; no process-to-test attribution is asserted'
        created_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    }
    $path = Join-Path $EvidenceRoot $script:D32H7CGitRunGrantName
    $ref = Write-D32H7CGitJsonCreateNew -Path $path -Document $doc
    return [PSCustomObject]@{ Document = $doc; Reference = $ref; Path = $path; Slots = @($slots.ToArray()); GitImage = $GitImage }
}

function Test-D32H7CGitRunGrant {
    param(
        [Parameter(Mandatory = $true)][object]$Reference,
        [Parameter(Mandatory = $true)][object]$Authority,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$CandidateSha,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][string]$EvidenceRoot,
        [Parameter(Mandatory = $true)][string]$TempRoot,
        [Parameter(Mandatory = $true)][string]$RunId,
        [Parameter(Mandatory = $true)][object]$OwnerMarker,
        [Parameter(Mandatory = $true)][object]$GitImage
    )
    if (-not (Test-D32Phase0ExactProperties -Object $Reference -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -or
        -not (Test-D32ProfilePathEqual -Left $Reference.path -Right (Join-Path $EvidenceRoot $script:D32H7CGitRunGrantName))) { throw 'H7C_GIT_GRANT_BLOCKED: grant file reference/path is not fixed' }
    $read = Read-D32H7CGitJsonFile -Path ([string]$Reference.path) -ExpectedSha256 ([string]$Reference.sha256)
    $null = Assert-D32H7CGitFileReferenceIdentity -Reference $Reference -Snapshot $read.Snapshot -Name 'H7-C per-run grant'
    $doc = $read.Document
    $fields = @('schema_version', 'record_type', 'status', 'authority', 'policy_sha256', 'candidate_sha', 'toolchain_profile', 'owner_marker', 'run_id', 'evidence_root', 'temp_root', 'git_image', 'fixed_suite', 'slots', 'parent_policy', 'job_policy', 'process_test_attribution', 'test_inventory', 'test_result_policy', 'created_at_utc')
    if (-not (Test-D32Phase0ExactProperties -Object $doc -Expected $fields) -or $doc.schema_version -ne 1 -or $doc.record_type -cne $script:D32H7CGitRunGrantType -or
        $doc.status -cne 'BOUND' -or $doc.policy_sha256 -cne $Authority.PolicySha256 -or $doc.candidate_sha -cne $CandidateSha -or $doc.run_id -cne $RunId -or
        (ConvertTo-Json -InputObject $doc.authority -Depth 6 -Compress) -cne (ConvertTo-Json -InputObject $Authority.Reference -Depth 6 -Compress) -or
        (ConvertTo-Json -InputObject $doc.toolchain_profile -Depth 6 -Compress) -cne (ConvertTo-Json -InputObject ([ordered]@{ path = $ValidatedProfile.ProfilePath; sha256 = $ValidatedProfile.Digest; bytes = [Int64]$ValidatedProfile.Identity.Bytes; volume_serial_hex = $ValidatedProfile.Identity.VolumeSerialHex; file_id_hex = $ValidatedProfile.Identity.FileIdHex }) -Depth 6 -Compress) -or
        (ConvertTo-Json -InputObject $doc.owner_marker -Depth 6 -Compress) -cne (ConvertTo-Json -InputObject $OwnerMarker -Depth 6 -Compress) -or
        -not (Test-D32ProfilePathEqual -Left $doc.evidence_root.path -Right $EvidenceRoot) -or
        $doc.evidence_root.volume_serial_hex -cne (Get-D32ProfileDirectoryIdentity -Path $EvidenceRoot).VolumeSerialHex -or
        $doc.evidence_root.file_id_hex -cne (Get-D32ProfileDirectoryIdentity -Path $EvidenceRoot).FileIdHex -or
        -not (Test-D32ProfilePathEqual -Left $doc.temp_root.path -Right $TempRoot) -or
        $doc.temp_root.volume_serial_hex -cne (Get-D32ProfileDirectoryIdentity -Path $TempRoot).VolumeSerialHex -or
        $doc.temp_root.file_id_hex -cne (Get-D32ProfileDirectoryIdentity -Path $TempRoot).FileIdHex -or
        (ConvertTo-Json -InputObject $doc.git_image -Depth 6 -Compress) -cne (ConvertTo-Json -InputObject ([ordered]@{ path = $GitImage.Path; bytes = [Int64]$GitImage.Bytes; sha256 = $GitImage.Sha256; volume_serial_hex = $GitImage.VolumeSerialHex; file_id_hex = $GitImage.FileIdHex }) -Depth 6 -Compress) -or
        (ConvertTo-Json -InputObject $doc.fixed_suite -Depth 16 -Compress) -cne (ConvertTo-Json -InputObject $Authority.Document.fixed_suite -Depth 16 -Compress) -or
        $doc.parent_policy -cne $Authority.Policy.parent_policy -or $doc.job_policy -cne $Authority.Policy.job_policy -or $doc.process_test_attribution -cne 'NONE' -or
        (ConvertTo-Json -InputObject $doc.test_inventory -Depth 5 -Compress) -cne (ConvertTo-Json -InputObject $script:D32H7CGitTestInventory -Depth 5 -Compress) -or
        $doc.test_result_policy -cne 'Every fixed H7-C libtest inventory item must appear exactly once in the full Vita suite log with result ok; no process-to-test attribution is asserted' -or
        $doc.slots -isnot [Array] -or $doc.slots.Count -ne $script:D32H7CGitSlotCount) { throw 'H7C_GIT_GRANT_BLOCKED: per-run grant candidate/profile/owner/root/temp/image/policy binding is invalid' }
    for ($i = 0; $i -lt $script:D32H7CGitSlotCount; $i++) {
        $expectedName = 'd32-h7c-slot-{0:D2}' -f ($i + 1)
        $slot = $doc.slots[$i]
        $slotPath = Join-Path $TempRoot $expectedName
        $repoPath = Join-Path $slotPath 'repo'
        $homePath = Join-Path $slotPath 'git-home'
        if (-not (Test-D32Phase0ExactProperties -Object $slot -Expected @('slot', 'path', 'repo', 'git_home', 'empty_git_config')) -or $slot.slot -cne $expectedName -or
            -not (Test-D32ProfilePathEqual -Left $slot.path.path -Right $slotPath) -or
            -not (Test-D32ProfilePathEqual -Left $slot.repo.path -Right $repoPath) -or
            -not (Test-D32ProfilePathEqual -Left $slot.git_home.path -Right $homePath)) { throw "H7C_GIT_GRANT_BLOCKED: slot path/order is invalid at index $i" }
        foreach ($directory in @($slot.path, $slot.repo, $slot.git_home)) { $null = Test-D32ProfileDirectoryIdentity -Path $directory.path -VolumeSerialHex $directory.volume_serial_hex -FileIdHex $directory.file_id_hex }
        $null = Test-D32Phase0FileReference -Reference $slot.empty_git_config -AllowedRoot $TempRoot
        if (-not (Test-D32ProfilePathEqual -Left $slot.empty_git_config.path -Right (Join-Path $homePath 'empty.gitconfig')) -or [Int64]$slot.empty_git_config.bytes -ne 0 -or $slot.empty_git_config.sha256 -cne 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') { throw "H7C_GIT_GRANT_BLOCKED: empty Git config reference is invalid at index $i" }
    }
    return [PSCustomObject]@{ Document = $doc; Reference = $Reference; Path = [string]$Reference.path; Slots = @($doc.slots); GitImage = $GitImage }
}

function Get-D32H7CGitTestResults {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Lines)
    $inventory = @($script:D32H7CGitTestInventory)
    if ($inventory.Count -ne 46 -or @($inventory | Select-Object -Unique).Count -ne 46) { throw 'H7C_GIT_TESTS_BLOCKED: code-owned fixed H7-C test inventory is not unique and complete' }
    $seen = @{}
    foreach ($line in $Lines) {
        if ($line -notmatch '^test\s+d29h7::tests::([A-Za-z0-9_]+)\s+\.\.\.\s+(ok|FAILED|ignored)(?:\s+\([^)]*\))?\s*$') { continue }
        $name = [string]$Matches[1]
        if ($name -notin $inventory) { continue }
        if ($seen.ContainsKey($name)) { throw "H7C_GIT_TESTS_BLOCKED: duplicate H7-C test result row: $name" }
        $seen[$name] = [string]$Matches[2]
    }
    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($name in $inventory) {
        if (-not $seen.ContainsKey($name)) { throw "H7C_GIT_TESTS_BLOCKED: required H7-C test result is absent: $name" }
        if ($seen[$name] -cne 'ok') { throw "H7C_GIT_TESTS_BLOCKED: required H7-C test did not pass: $name=$($seen[$name])" }
        $results.Add([ordered]@{ name = $name; result = 'ok' })
    }
    return @($results.ToArray())
}

function Get-D32H7CGitEnvironmentMap {
    param([Parameter(Mandatory = $true)][object]$Environment)
    $map = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
    if ($Environment -is [System.Collections.IDictionary]) {
        foreach ($key in $Environment.Keys) {
            if (-not $map.TryAdd([string]$key, [string]$Environment[$key])) { throw 'H7C_GIT_ATTESTATION_BLOCKED: native environment has duplicate keys' }
        }
    } else {
        foreach ($property in $Environment.PSObject.Properties) {
            if (-not $map.TryAdd([string]$property.Name, [string]$property.Value)) { throw 'H7C_GIT_ATTESTATION_BLOCKED: native environment has duplicate keys' }
        }
    }
    return $map
}

function ConvertTo-D32H7CGitObservationDocument {
    param([Parameter(Mandatory = $true)][object]$Observation)
    $environment = Get-D32H7CGitEnvironmentMap -Environment $Observation.Environment
    $environmentDocument = [ordered]@{}
    foreach ($key in @($environment.Keys | Sort-Object -CaseSensitive)) { $environmentDocument[[string]$key] = [string]$environment[[string]$key] }
    return [ordered]@{
        slot = [string]$Observation.Slot; operation = [string]$Observation.Operation
        process_id = [uint32]$Observation.ProcessId; creation_filetime = [Int64]$Observation.CreationFileTime
        parent_process_id = [uint32]$Observation.ParentProcessId; parent_creation_filetime = [Int64]$Observation.ParentCreationFileTime
        image_path = [string]$Observation.ImagePath; bytes = [Int64]$Observation.Bytes; sha256 = [string]$Observation.Sha256
        volume_serial_hex = [string]$Observation.VolumeSerialHex; file_id_hex = [string]$Observation.FileIdHex
        command_line = [string]$Observation.CommandLine; argv = @($Observation.Argv); working_directory = [string]$Observation.WorkingDirectory
        environment = $environmentDocument
    }
}

function Assert-D32H7CGitObservationSet {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$GitChildren, [Parameter(Mandatory = $true)][object]$RunGrant,
        [Parameter(Mandatory = $true)][object]$Trace, [Parameter(Mandatory = $true)][object]$GitImage, [Parameter(Mandatory = $true)][string]$Repository)
    if ($GitChildren.Count -gt 210 -or $Trace.processes -isnot [Array]) { throw 'H7C_GIT_ATTESTATION_BLOCKED: Git child count or V2 process table exceeds the finite grant' }
    $traceGit = @($Trace.processes | Where-Object { Test-D32ProfilePathEqual -Left $_.image_path -Right $GitImage.Path })
    if ($traceGit.Count -ne $GitChildren.Count) { throw 'H7C_GIT_ATTESTATION_BLOCKED: native Git CREATE observations do not reconcile one-to-one with V2 process records' }
    $slots = @{}
    foreach ($slot in @($RunGrant.Document.slots)) { $slots[[string]$slot.slot] = $slot }
    $counts = @{}
    $sequenceByIdentity = @{}
    $identitySet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($child in $GitChildren) {
        if (-not (Test-D32Phase0ExactProperties -Object $child -Expected @('slot', 'operation', 'process_id', 'creation_filetime', 'parent_process_id', 'parent_creation_filetime', 'image_path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex', 'command_line', 'argv', 'working_directory', 'environment')) -or
            -not $slots.ContainsKey([string]$child.slot) -or $child.argv -isnot [Array] -or @($child.argv | Where-Object { $_ -isnot [string] }).Count -ne 0) { throw 'H7C_GIT_ATTESTATION_BLOCKED: native Git observation does not match a fixed finite slot/schema' }
        $environmentMap = Get-D32H7CGitEnvironmentMap -Environment $child.environment
        $slot = $slots[[string]$child.slot]
        if (-not (Test-D32Phase0Integer -Value $child.process_id -Positive) -or -not (Test-D32Phase0Integer -Value $child.creation_filetime -Positive) -or
            -not (Test-D32Phase0Integer -Value $child.parent_process_id -Positive) -or -not (Test-D32Phase0Integer -Value $child.parent_creation_filetime -Positive) -or
            -not (Test-D32ProfilePathEqual -Left $child.image_path -Right $GitImage.Path) -or [Int64]$child.bytes -ne [Int64]$GitImage.Bytes -or
            $child.sha256 -cne $GitImage.Sha256 -or $child.volume_serial_hex -cne $GitImage.VolumeSerialHex -or $child.file_id_hex -cne $GitImage.FileIdHex -or
            -not (Test-D32ProfilePathEqual -Left $child.working_directory -Right $slot.repo.path) -or
            -not (Test-D32ProfilePathEqual -Left $child.argv[0] -Right $GitImage.Path)) { throw "H7C_GIT_ATTESTATION_BLOCKED: native Git image/slot/path/argv/environment identity is malformed: $($child.process_id)" }
        $key = "$($child.process_id)|$($child.creation_filetime)"
        if (-not $identitySet.Add($key)) { throw "H7C_GIT_ATTESTATION_BLOCKED: duplicate native child identity: $key" }
        $traceMatch = @($traceGit | Where-Object { $_.process_id -eq $child.process_id -and $_.creation_filetime -eq $child.creation_filetime })
        if ($traceMatch.Count -ne 1 -or $traceMatch[0].parent_process_id -ne $child.parent_process_id -or $traceMatch[0].parent_creation_filetime -ne $child.parent_creation_filetime -or
            $traceMatch[0].allowed_image_reason -cne 'narrow-caller-pinned-H7C-Git-child-v1') { throw "H7C_GIT_ATTESTATION_BLOCKED: native child and V2 trace PID/creation/parent/image reason differ: $key" }
        $sequenceByIdentity[$key] = [Int64]$traceMatch[0].create_sequence
        $parent = @($Trace.processes | Where-Object { $_.process_id -eq $child.parent_process_id -and $_.creation_filetime -eq $child.parent_creation_filetime })
        $root = @($Trace.processes | Where-Object { $_.create_sequence -eq 1 })
        if ($parent.Count -ne 1 -or $root.Count -ne 1 -or $parent[0].parent_process_id -ne $root[0].process_id -or
            $parent[0].parent_creation_filetime -ne $root[0].creation_filetime -or
            -not (Test-D32ProfilePathWithin -Child $parent[0].image_path -Parent (Join-Path $Repository 'vita-agent\target\debug\deps')) -or
            [IO.Path]::GetFileName([string]$parent[0].image_path) -cnotmatch '^vita_agent-[0-9a-f]+\.exe$') { throw "H7C_GIT_ATTESTATION_BLOCKED: Git parent is not the exact candidate Vita libtest directly below Cargo root: $key" }
        $argv = Get-D32H7CGitFixedArgv
        $arguments = @($child.argv | Select-Object -Skip 1)
        $operationIndex = -1
        for ($i = 0; $i -lt $argv.setup.Count; $i++) { if (($arguments -join "`0") -ceq ($argv.setup[$i] -join "`0")) { $operationIndex = $i; break } }
        $operationKey = ''
        if ($operationIndex -ge 0) { $operationKey = 'setup-{0:D2}' -f ($operationIndex + 1) }
        elseif (($arguments -join "`0") -ceq ($argv.status -join "`0")) { $operationKey = 'status' }
        if ($child.operation -cnotin @('setup-01', 'setup-02', 'setup-03', 'setup-04', 'setup-05', 'status') -or $child.operation -cne $operationKey -or
            $child.command_line -cne (ConvertTo-D32Phase0CommandLine -Arguments (@($GitImage.Path) + $arguments))) { throw "H7C_GIT_ATTESTATION_BLOCKED: Git argv/operation pair is outside the finite setup/status policy: $key" }
        $expectedEnvironmentKeys = if ($child.operation -ceq 'status') {
            @('COMSPEC', 'GCM_INTERACTIVE', 'GIT_CEILING_DIRECTORIES', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_NOSYSTEM', 'GIT_OPTIONAL_LOCKS', 'GIT_TERMINAL_PROMPT', 'HOME', 'SystemDrive', 'SystemRoot', 'windir')
        } else {
            @('GCM_INTERACTIVE', 'GIT_CEILING_DIRECTORIES', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_NOSYSTEM', 'GIT_CONFIG_SYSTEM', 'GIT_NO_REPLACE_OBJECTS', 'GIT_OPTIONAL_LOCKS', 'GIT_PAGER', 'GIT_TERMINAL_PROMPT', 'HOME', 'TEMP', 'TMP', 'USERPROFILE', 'WINDIR', 'SystemRoot', 'XDG_CONFIG_HOME')
        }
        $actualEnvironmentKeys = @($environmentMap.Keys | ForEach-Object { [string]$_ } | Sort-Object)
        $sortedExpectedEnvironmentKeys = @($expectedEnvironmentKeys | Sort-Object)
        if (($actualEnvironmentKeys -join '|') -cne ($sortedExpectedEnvironmentKeys -join '|')) { throw "H7C_GIT_ATTESTATION_BLOCKED: Git environment key set differs from the fixed $(if ($child.operation -ceq 'status') { 'status' } else { 'setup' }) map: $key" }
        $systemRoot = [string]$environmentMap['SystemRoot']
        $windowsRootOk = $systemRoot -match '^[A-Za-z]:\\[^:*?"<>|]+$' -and (Test-D32ProfileCanonicalPathString -Path $systemRoot) -and (Test-D32ProfileNoReparsePath -Path $systemRoot) -and
            [String]::Equals([string]$environmentMap['WINDIR'], $systemRoot, [StringComparison]::OrdinalIgnoreCase) -and
            (($child.operation -cne 'status') -or [String]::Equals([string]$environmentMap['windir'], $systemRoot, [StringComparison]::OrdinalIgnoreCase))
        $envExpected = @{
            GCM_INTERACTIVE = 'Never'; GIT_CEILING_DIRECTORIES = [string]$slot.path.path; GIT_CONFIG_GLOBAL = [string]$slot.empty_git_config.path
            GIT_CONFIG_NOSYSTEM = '1'; GIT_OPTIONAL_LOCKS = '0'; GIT_TERMINAL_PROMPT = '0'; HOME = [string]$slot.git_home.path
        }
        if ($child.operation -ceq 'status') {
            $envExpected.SystemDrive = ([IO.Path]::GetPathRoot($systemRoot)).TrimEnd('\')
            $envExpected.COMSPEC = Join-Path (Join-Path $systemRoot 'System32') 'cmd.exe'
        } else {
            $envExpected.GIT_CONFIG_SYSTEM = [string]$slot.empty_git_config.path; $envExpected.GIT_NO_REPLACE_OBJECTS = '1'; $envExpected.GIT_PAGER = 'cat'
            $envExpected.TEMP = [string]$RunGrant.Document.temp_root.path; $envExpected.TMP = [string]$RunGrant.Document.temp_root.path
            $envExpected.USERPROFILE = [string]$slot.git_home.path; $envExpected.XDG_CONFIG_HOME = [string]$slot.git_home.path
        }
        if (-not $windowsRootOk) { throw "H7C_GIT_ATTESTATION_BLOCKED: Git child Windows root environment is not canonical/equal: $key" }
        foreach ($envKey in $envExpected.Keys) {
            $actualValue = [string]$environmentMap[$envKey]
            if ($envKey -in @('GIT_CEILING_DIRECTORIES', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM', 'HOME', 'TEMP', 'TMP', 'USERPROFILE', 'XDG_CONFIG_HOME', 'COMSPEC')) {
                if (-not (Test-D32ProfilePathEqual -Left $actualValue -Right ([string]$envExpected[$envKey]))) { throw "H7C_GIT_ATTESTATION_BLOCKED: Git child environment path $envKey differs: $key" }
            } elseif ($actualValue -cne [string]$envExpected[$envKey]) { throw "H7C_GIT_ATTESTATION_BLOCKED: Git child environment value $envKey differs: $key" }
        }
        if (-not $counts.ContainsKey([string]$child.slot)) { $counts[[string]$child.slot] = [System.Collections.Generic.List[object]]::new() }
        $counts[[string]$child.slot].Add($child)
    }
    foreach ($slotName in $counts.Keys) {
        $events = @($counts[$slotName].ToArray() | Sort-Object { $sequenceByIdentity["$($_.process_id)|$($_.creation_filetime)"] })
        $setupSequence = @($events | Where-Object { $_.operation -like 'setup-*' } | ForEach-Object { [string]$_.operation })
        $expectedSetup = @('setup-01', 'setup-02', 'setup-03', 'setup-04', 'setup-05')
        $expectedPrefix = @($expectedSetup | Select-Object -First $setupSequence.Count)
        $statusEvents = @($events | Where-Object { $_.operation -ceq 'status' })
        if ($setupSequence.Count -gt 5 -or ($setupSequence -join '|') -cne ($expectedPrefix -join '|') -or $statusEvents.Count -gt 1 -or
            ($statusEvents.Count -eq 1 -and $setupSequence.Count -ne 5)) {
            throw "H7C_GIT_ATTESTATION_BLOCKED: per-slot Git operations exceed/reorder finite action caps: $slotName"
        }
        $lastSetup = @($events | Where-Object { $_.operation -like 'setup-*' } | Select-Object -Last 1)
        if ($statusEvents.Count -eq 1 -and $lastSetup.Count -eq 1 -and $sequenceByIdentity["$($statusEvents[0].process_id)|$($statusEvents[0].creation_filetime)"] -lt $sequenceByIdentity["$($lastSetup[0].process_id)|$($lastSetup[0].creation_filetime)"]) { throw "H7C_GIT_ATTESTATION_BLOCKED: status precedes setup completion for $slotName" }
    }
    return $true
}

function New-D32H7CGitChildAttestation {
    param(
        [Parameter(Mandatory = $true)][object]$Authority,
        [Parameter(Mandatory = $true)][object]$RunGrant,
        [Parameter(Mandatory = $true)][object]$OwnerBinding,
        [Parameter(Mandatory = $true)][object]$Phase0Command,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$SuiteLines,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$GitChildren,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$CandidateSha,
        [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][string]$EvidenceRoot,
        [Parameter(Mandatory = $true)][string]$TempRoot,
        [Parameter(Mandatory = $true)][object]$GitImage
    )
    if ($Phase0Command.name -cne 'vita-full-local-suite' -or $Phase0Command.exit_code -ne 0 -or
        -not (Test-D32ProfilePathEqual -Left $Phase0Command.executable -Right $ValidatedProfile.Profile.toolchain.cargo.path) -or
        -not (Test-D32ProfilePathEqual -Left $Phase0Command.working_directory -Right $Repository)) { throw 'H7C_GIT_ATTESTATION_BLOCKED: companion must bind the one fixed successful Vita suite command' }
    $testResults = @(Get-D32H7CGitTestResults -Lines $SuiteLines)
    $null = Assert-D32H7CGitObservationSet -GitChildren $GitChildren -RunGrant $RunGrant -Trace $Phase0Command.process_trace -GitImage $GitImage -Repository $Repository
    $keys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $traceGit = @($Phase0Command.process_trace.processes | Where-Object { Test-D32ProfilePathEqual -Left $_.image_path -Right $GitImage.Path })
    foreach ($child in $GitChildren) {
        if (-not (Test-D32Phase0ExactProperties -Object $child -Expected @('slot', 'operation', 'process_id', 'creation_filetime', 'parent_process_id', 'parent_creation_filetime', 'image_path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex', 'command_line', 'argv', 'working_directory', 'environment'))) { throw 'H7C_GIT_ATTESTATION_BLOCKED: native child observation schema differs' }
        $key = "$($child.process_id)|$($child.creation_filetime)"
        if (-not $keys.Add($key)) { throw 'H7C_GIT_ATTESTATION_BLOCKED: duplicate child identity in native observations' }
        $matches = @($traceGit | Where-Object { $_.process_id -eq $child.process_id -and $_.creation_filetime -eq $child.creation_filetime })
        if ($matches.Count -ne 1 -or $matches[0].parent_process_id -ne $child.parent_process_id -or $matches[0].parent_creation_filetime -ne $child.parent_creation_filetime -or
            $child.sha256 -cne $GitImage.Sha256 -or [Int64]$child.bytes -ne [Int64]$GitImage.Bytes -or $child.volume_serial_hex -cne $GitImage.VolumeSerialHex -or $child.file_id_hex -cne $GitImage.FileIdHex) { throw "H7C_GIT_ATTESTATION_BLOCKED: native Git child differs from V2 trace identity $key" }
    }
    $traceJson = ConvertTo-Json -InputObject $Phase0Command.process_trace -Depth 40 -Compress
    $traceSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes($traceJson))).ToLowerInvariant()
    $doc = [ordered]@{
        schema_version = 1; record_type = $script:D32H7CGitChildAttestationType; status = 'PASS'; candidate_sha = $CandidateSha
        toolchain_profile = [ordered]@{ path = $ValidatedProfile.ProfilePath; sha256 = $ValidatedProfile.Digest; bytes = [Int64]$ValidatedProfile.Identity.Bytes; volume_serial_hex = $ValidatedProfile.Identity.VolumeSerialHex; file_id_hex = $ValidatedProfile.Identity.FileIdHex }
        authority = $Authority.Reference; run_grant = $RunGrant.Reference; owner_marker = $OwnerBinding.MarkerReference; run_id = [string]$OwnerBinding.RunId
        evidence_root = [ordered]@{ path = $EvidenceRoot; volume_serial_hex = [string]$OwnerBinding.EvidenceRootIdentity.VolumeSerialHex; file_id_hex = [string]$OwnerBinding.EvidenceRootIdentity.FileIdHex }
        temp_root = [ordered]@{ path = $TempRoot; volume_serial_hex = [string]$RunGrant.Document.temp_root.volume_serial_hex; file_id_hex = [string]$RunGrant.Document.temp_root.file_id_hex }
        git_image = [ordered]@{ path = $GitImage.Path; bytes = [Int64]$GitImage.Bytes; sha256 = $GitImage.Sha256; volume_serial_hex = $GitImage.VolumeSerialHex; file_id_hex = $GitImage.FileIdHex }
        fixed_suite = [ordered]@{ name = $Phase0Command.name; executable = $Phase0Command.executable; executable_sha256 = $Phase0Command.executable_sha256; executable_bytes = [Int64]$Phase0Command.executable_bytes; executable_volume_serial_hex = $Phase0Command.executable_volume_serial_hex; executable_file_id_hex = $Phase0Command.executable_file_id_hex; arguments = @($Phase0Command.arguments); command_line = $Phase0Command.command_line; working_directory = $Phase0Command.working_directory; timeout_seconds = [int]$Authority.Document.fixed_suite.timeout_seconds; candidate_sha_environment = [ordered]@{ name = 'D32_EXPECTED_CANDIDATE_SHA'; value = $CandidateSha }; exit_code = [int]$Phase0Command.exit_code; stdout = $Phase0Command.stdout; stderr = $Phase0Command.stderr; process_trace_sha256 = $traceSha }
        test_attribution = 'NONE'; test_inventory = @($testResults); git_child_count = [int]$GitChildren.Count; git_children = @($GitChildren); policy_sha256 = [string]$Authority.PolicySha256; generated_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    }
    $path = Join-Path $EvidenceRoot $script:D32H7CGitAttestationName
    return [PSCustomObject]@{ Document = $doc; Reference = (Write-D32H7CGitJsonCreateNew -Path $path -Document $doc); Path = $path }
}

function Test-D32H7CGitChildAttestation {
    param(
        [Parameter(Mandatory = $true)][object]$Reference, [Parameter(Mandatory = $true)][object]$Authority,
        [Parameter(Mandatory = $true)][object]$RunGrant, [Parameter(Mandatory = $true)][object]$OwnerBinding,
        [Parameter(Mandatory = $true)][object]$Phase0Command, [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$CandidateSha, [Parameter(Mandatory = $true)][object]$ValidatedProfile,
        [Parameter(Mandatory = $true)][string]$EvidenceRoot, [Parameter(Mandatory = $true)][string]$TempRoot,
        [Parameter(Mandatory = $true)][object]$GitImage
    )
    if (-not (Test-D32Phase0ExactProperties -Object $Reference -Expected @('path', 'bytes', 'sha256', 'volume_serial_hex', 'file_id_hex')) -or
        -not (Test-D32ProfilePathEqual -Left $Reference.path -Right (Join-Path $EvidenceRoot $script:D32H7CGitAttestationName))) { throw 'H7C_GIT_ATTESTATION_BLOCKED: companion reference is not at the fixed create-new path' }
    $read = Read-D32H7CGitJsonFile -Path ([string]$Reference.path) -ExpectedSha256 ([string]$Reference.sha256)
    $null = Assert-D32H7CGitFileReferenceIdentity -Reference $Reference -Snapshot $read.Snapshot -Name 'H7-C child attestation'
    $doc = $read.Document
    $fields = @('schema_version', 'record_type', 'status', 'candidate_sha', 'toolchain_profile', 'authority', 'run_grant', 'owner_marker', 'run_id', 'evidence_root', 'temp_root', 'git_image', 'fixed_suite', 'test_attribution', 'test_inventory', 'git_child_count', 'git_children', 'policy_sha256', 'generated_at_utc')
    if (-not (Test-D32Phase0ExactProperties -Object $doc -Expected $fields) -or $doc.schema_version -ne 1 -or $doc.record_type -cne $script:D32H7CGitChildAttestationType -or $doc.status -cne 'PASS' -or
        $doc.candidate_sha -cne $CandidateSha -or $doc.run_id -cne $OwnerBinding.RunId -or $doc.policy_sha256 -cne $Authority.PolicySha256 -or $doc.test_attribution -cne 'NONE' -or
        (ConvertTo-Json -InputObject $doc.authority -Depth 6 -Compress) -cne (ConvertTo-Json -InputObject $Authority.Reference -Depth 6 -Compress) -or
        (ConvertTo-Json -InputObject $doc.run_grant -Depth 6 -Compress) -cne (ConvertTo-Json -InputObject $RunGrant.Reference -Depth 6 -Compress) -or
        (ConvertTo-Json -InputObject $doc.owner_marker -Depth 6 -Compress) -cne (ConvertTo-Json -InputObject $OwnerBinding.MarkerReference -Depth 6 -Compress) -or
        -not (Test-D32ProfilePathEqual -Left $doc.evidence_root.path -Right $EvidenceRoot) -or $doc.evidence_root.volume_serial_hex -cne $OwnerBinding.EvidenceRootIdentity.VolumeSerialHex -or $doc.evidence_root.file_id_hex -cne $OwnerBinding.EvidenceRootIdentity.FileIdHex -or
        -not (Test-D32ProfilePathEqual -Left $doc.temp_root.path -Right $TempRoot) -or $doc.temp_root.volume_serial_hex -cne $RunGrant.Document.temp_root.volume_serial_hex -or $doc.temp_root.file_id_hex -cne $RunGrant.Document.temp_root.file_id_hex -or
        -not (Test-D32Phase0ExactProperties -Object $doc.toolchain_profile -Expected @('path', 'sha256', 'bytes', 'volume_serial_hex', 'file_id_hex')) -or
        -not (Test-D32ProfilePathEqual -Left $doc.toolchain_profile.path -Right $ValidatedProfile.ProfilePath) -or $doc.toolchain_profile.sha256 -cne $ValidatedProfile.Digest -or
        [Int64]$doc.toolchain_profile.bytes -ne [Int64]$ValidatedProfile.Identity.Bytes -or $doc.toolchain_profile.volume_serial_hex -cne $ValidatedProfile.Identity.VolumeSerialHex -or $doc.toolchain_profile.file_id_hex -cne $ValidatedProfile.Identity.FileIdHex -or
        $doc.test_inventory -isnot [Array] -or $doc.test_inventory.Count -ne 46 -or $doc.git_children -isnot [Array] -or $doc.git_child_count -ne $doc.git_children.Count) { throw 'H7C_GIT_ATTESTATION_BLOCKED: companion strict schema/candidate/profile/owner/root/grant binding differs' }
    $expectedTraceJson = ConvertTo-Json -InputObject $Phase0Command.process_trace -Depth 40 -Compress
    $expectedTraceSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes($expectedTraceJson))).ToLowerInvariant()
    $suiteLines = @(Get-D32Phase0TextFromLogs -CommandRecord $Phase0Command)
    $expectedTestResults = @(Get-D32H7CGitTestResults -Lines $suiteLines)
    if (-not (Test-D32Phase0ExactProperties -Object $doc.fixed_suite -Expected @('name', 'executable', 'executable_sha256', 'executable_bytes', 'executable_volume_serial_hex', 'executable_file_id_hex', 'arguments', 'command_line', 'working_directory', 'timeout_seconds', 'candidate_sha_environment', 'exit_code', 'stdout', 'stderr', 'process_trace_sha256')) -or
        -not (Test-D32Phase0ExactProperties -Object $doc.fixed_suite.candidate_sha_environment -Expected @('name', 'value')) -or
        $doc.fixed_suite.candidate_sha_environment.name -cne 'D32_EXPECTED_CANDIDATE_SHA' -or $doc.fixed_suite.candidate_sha_environment.value -cne $CandidateSha -or
        $doc.fixed_suite.name -cne 'vita-full-local-suite' -or $doc.fixed_suite.exit_code -ne 0 -or
        [Int64]$doc.fixed_suite.timeout_seconds -ne [Int64]$Authority.Document.fixed_suite.timeout_seconds -or
        $doc.fixed_suite.process_trace_sha256 -cne $expectedTraceSha -or
        $doc.fixed_suite.executable_sha256 -cne $Phase0Command.executable_sha256 -or
        [Int64]$doc.fixed_suite.executable_bytes -ne [Int64]$Phase0Command.executable_bytes -or
        $doc.fixed_suite.executable_volume_serial_hex -cne $Phase0Command.executable_volume_serial_hex -or
        $doc.fixed_suite.executable_file_id_hex -cne $Phase0Command.executable_file_id_hex -or
        (ConvertTo-Json -InputObject $doc.fixed_suite.arguments -Depth 8 -Compress) -cne (ConvertTo-Json -InputObject $Phase0Command.arguments -Depth 8 -Compress) -or
        $doc.fixed_suite.command_line -cne $Phase0Command.command_line -or -not (Test-D32ProfilePathEqual -Left $doc.fixed_suite.executable -Right $Phase0Command.executable) -or
        (ConvertTo-Json -InputObject $doc.fixed_suite.stdout -Depth 6 -Compress) -cne (ConvertTo-Json -InputObject $Phase0Command.stdout -Depth 6 -Compress) -or
        (ConvertTo-Json -InputObject $doc.fixed_suite.stderr -Depth 6 -Compress) -cne (ConvertTo-Json -InputObject $Phase0Command.stderr -Depth 6 -Compress) -or
        -not (Test-D32ProfilePathEqual -Left $doc.fixed_suite.working_directory -Right $Repository)) { throw 'H7C_GIT_ATTESTATION_BLOCKED: companion fixed-suite command binding differs' }
    $null = Test-D32Phase0FileReference -Reference $doc.fixed_suite.stdout -AllowedRoot $EvidenceRoot
    $null = Test-D32Phase0FileReference -Reference $doc.fixed_suite.stderr -AllowedRoot $EvidenceRoot
    if ((ConvertTo-Json -InputObject $doc.test_inventory -Depth 8 -Compress) -cne (ConvertTo-Json -InputObject $expectedTestResults -Depth 8 -Compress)) { throw 'H7C_GIT_ATTESTATION_BLOCKED: companion H7-C test-result inventory does not match the current captured full-suite stdout/stderr' }
    for ($i = 0; $i -lt $script:D32H7CGitTestInventory.Count; $i++) {
        if (-not (Test-D32Phase0ExactProperties -Object $doc.test_inventory[$i] -Expected @('name', 'result')) -or $doc.test_inventory[$i].name -cne $script:D32H7CGitTestInventory[$i] -or $doc.test_inventory[$i].result -cne 'ok') { throw "H7C_GIT_ATTESTATION_BLOCKED: required H7-C test result differs at index $i" }
    }
    $null = Assert-D32H7CGitObservationSet -GitChildren @($doc.git_children) -RunGrant $RunGrant -Trace $Phase0Command.process_trace -GitImage $GitImage -Repository $Repository
    return [PSCustomObject]@{ Document = $doc; Reference = (Get-D32H7CGitExternalFileReference -Path ([string]$Reference.path)); Digest = [string]$Reference.sha256 }
}
