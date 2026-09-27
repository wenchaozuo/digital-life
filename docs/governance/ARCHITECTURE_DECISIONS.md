# ARCHITECTURE_DECISIONS.md

> 只记录已经由架构权威明确批准的决定。
>
> **候选方案、讨论稿、Codex 自己的偏好不得标记为 APPROVED。**
> 建议按 ADR 编号追加，不覆盖历史。

---

## ADR 索引

| ID | 状态 | 主题 | 决策来源 | 生效范围 |
|---|---|---|---|---|
| ADR-TEMPLATE | TEMPLATE | 示例占位 | - | - |
| ADR-D32-EVIDENCE-BUNDLE-V1 | APPROVED | D32-A gate evidence bundle 与 clean-source release attestation | GPT-6 Sol | D32-A preflight/evidence only |
| ADR-D32-FIXTURE-TRUST-D31-SEEDER | APPROVED | D32 fixture Git trust 与 D31 recovery seeder evidence | GPT-6 Sol | D32 fixture tooling 与 D31 test-helper evidence only |
| ADR-D32-RELEASE-EVIDENCE-BOOTSTRAP | APPROVED WITH CONDITIONS | D32-A release evidence bundle 两阶段 bootstrap | GPT-6 Sol | D32-A bundle bootstrap ordering only |
| ADR-D32-PHASE0-TOOLCHAIN-PROFILE | APPROVED WITH CONDITIONS | D32 Phase 0 本地矩阵与 caller-pinned build toolchain | GPT-6 Sol | D32 Phase 0 与紧邻 bundle evidence build only |
| ADR-D32-PROCESS-EVENT-TRACE-V1 | SUPERSEDED | D32 Phase 0/release evidence command-processor denial and complete process trace (historical trace-source conditions) | GPT-6 Sol Max | Historical; superseded for implementation by V2 |
| ADR-D32-PROCESS-EVENT-TRACE-V2 | APPROVED | Synchronous Win32 debug events plus independent Job accounting | GPT-6 Sol Max | D32 Phase 0、release evidence build 与相应 provenance only |
| ADR-D32-GOVERNANCE-V12-RECONCILIATION | APPROVED WITH CONDITIONS | D32 candidate governance v1.2 reconciliation and prospective SC-D32-V1 | GPT-6 Sol Max | D32 final-gate candidate only |
| ADR-D32-PINNED-GIT-ROOT-IDENTITY | APPROVED WITH CONDITIONS | D32 fixture tooling caller-pinned direct Git root identity under V2 trace | GPT-6 Sol Max | D32 fixture Git metadata queries only |
| ADR-D32-RELEASE-OUTPUT-FRESHNESS-QUARANTINE | APPROVED WITH CONDITIONS | Exact D32 release-output freshness quarantine exception | GPT-6 Sol Max | Three named Phase 1 release leaves only |

### ADR-D32-EVIDENCE-BUNDLE-V1 — D32-A Gate Evidence Bundle 与 Build Attestation

**Status:** APPROVED
**Decision authority:** GPT-6 Sol
**Decision date:** 2026-09-23
**Related milestone:** D32-A final-gate evidence
**Related baseline:** `7923794565f6742fbfd760c2f3b01e9dd18abd42` (D32 stage base); repair-lineage base: `4c727ec5ba42e0288400d5847b43b08a1c96bc54`

#### Context

The existing bundle manifest can describe matching files, but it does not independently establish that the fixed release commands completed for the exact clean candidate. D32 gate evidence must also stay separate from the Tauri shipping package.

#### Decision

1. D32 gate evidence is a separate, external-to-clone evidence output. Its dedicated `d32-gate-bundle` directory contains exactly three flat artifacts plus `BUNDLE-MANIFEST.json`: `vita-agent.exe`, `d32a-production-canary-host.exe`, and `digital_life_lib.dll`. The build attestation is a sibling file named `D32-RELEASE-ATTESTATION.json`; the manifest binds its exact SHA-256.
2. Artifact source paths are fixed to `vita-agent/target/release/vita-agent.exe` and `src-tauri/target/release/{d32a-production-canary-host.exe,digital_life_lib.dll}`. The attestor itself runs only the fixed locked release Cargo commands, pins their `--target-dir` outputs to `vita-agent/target` and `src-tauri/target`, records completion/exit/process identity, and records the exact candidate SHA plus clean Git status before and after each command. Before starting either command, it must fail closed if any of the three exact release artifact paths already exists; it does not move or delete prior output. The attestation records each source artifact's path, bytes, SHA-256, and file identity. On Windows, file identity includes volume serial and 128-bit file ID read from the same opened handle used to hash the bytes, alongside length, timestamps, attributes, and absolute path. The validator independently checks the attestation and current bytes.
3. `runtime_resources` in this gate-only manifest is exactly `[]`. This does not describe or alter the installer package. The validator checks that the existing sole Tauri resource mapping remains `../vita-agent/target/release/vita-agent.exe` -> `vita-agent.exe`.

#### Frozen invariants

1. No frozen product behavior, protocol, persistent schema, identity continuity, authority ownership, grant/revoke semantics, or security boundary changes are authorized by this decision.
2. Host official preflight and retained-handle checks remain the security authority. PowerShell path/hash/file-identity checks are advisory evidence and do not replace Host authority.
3. Tauri shipping configuration and package contents are unchanged; the D32 evidence bundle is not an installer input.

#### Allowed implementation space

- Implement the fixed release evidence attestor and strict validator in `scripts/d32-preflight.ps1` (or an equivalent D32 evidence script).
- Emit evidence only under a new absolute output directory outside and non-overlapping with the candidate clone; do not overwrite an existing output.
- Require PowerShell 7.5 or later for the timestamp parsing contract; fail fast on an older runtime.
- Add validator SelfTest positive and negative cases and update this decision index/body. A required reparse-point negative that cannot be created on the current OS/filesystem is `UNAVAILABLE` and blocks an overall SelfTest PASS.

#### Forbidden implementation

- Do not modify Rust/Host production code, `tauri.conf.json`, installer resources, frozen product/protocol/authority, fixture-prebuild behavior, or any user/provider/Codex secret/configuration.
- Do not mark D32 gates PASS from generated manifest/attestation alone or infer real-canary completion from this tooling.

#### Required tests

- Run the preflight `-SelfTest` on the candidate validator, including exact/unique schema, duplicate JSON keys/artifacts, nested command/build-target/identity missing/extra/wrong-type cases, fixed paths, command/clean-state binding, exact hashes/bytes/identity, empty resources, flat-only contents, and Tauri map negatives.
- For an operational evidence run, record the exact candidate SHA and clean Git checks before and after each fixed release build; validate the produced manifest and attestation together before expensive gates.
- Same-bytes/restored-metadata file replacement must be rejected through the opened-handle volume/file identity. Reparse-point rejection is tested where the platform can create the fixture; if not, it is explicitly `UNAVAILABLE` and the overall SelfTest is `BLOCKED`, never PASS. A concurrent TOCTOU race is not claimed as SelfTest coverage; Host retained-handle gates remain required.

#### Required real canary

- This ADR closes no D32-A real canary. All eight ordered real Host modes and their required negative evidence remain mandatory on the same exact candidate.

#### Required negative evidence

- Missing/extra/duplicate schema entries, duplicated/missing artifacts, wrong-type nested command/build-target/identity values, pre-existing exact release outputs, wrong candidate or attestation SHA, missing/stale attestation, wrong release command, dirty attestation, wrong source/destination path, corrupted bytes, same-bytes replacement with restored metadata, non-empty runtime resources, extra/nested/reparse bundle contents, stale file identity, and changed Tauri resource mapping must be rejected.
- If a reparse-point fixture cannot be created, report it as unavailable and block overall SelfTest PASS; do not convert it into PASS. No repeatable concurrent TOCTOU race injection is asserted by SelfTest.

#### Compatibility constraints

- Preserve the frozen product/protocol/authority surfaces and existing Tauri shipping resource mapping. The gate bundle is an evidence artifact only.
- Exact SHA, clean tree, fixed build commands, absent-before-build proof for the three exact outputs, source paths, output schema, opened-handle volume/file identity, and manifest-to-attestation hash binding are mandatory.

#### Escalation triggers

- Any need to alter Host retained-handle authority, shipping package/resource mapping, product/protocol/authority semantics, or frozen architecture requires Sol arbitration before implementation.

#### Supersedes / Superseded by

- Supersedes none. This decision does not supersede D32-A gate requirements or grant freeze authority.

---

### ADR-D32-FIXTURE-TRUST-D31-SEEDER — D32 Fixture Git Trust 与 D31 Recovery Seeder Evidence

**Status:** APPROVED
**Decision authority:** GPT-6 Sol
**Decision date:** 2026-09-23
**Related milestone:** D32 fixture evidence and D31 recovery real-process test support
**Related baseline:** `7923794565f6742fbfd760c2f3b01e9dd18abd42` (D32 stage base); repair-lineage base: `4c727ec5ba42e0288400d5847b43b08a1c96bc54`

#### Context

D32 fixture production and validation need independent Git executable identity and clean-candidate checks. The D31 real-process recovery test also needs a purpose-built helper image without changing the existing fixture schema or shipping sidecar.

#### Decision

1. D32 fixture producer and consumer require a caller-pinned absolute Git executable path and its exact expected SHA-256. They validate the executable as a regular non-reparse file, sanitize inherited Git environment/configuration, and verify the exact candidate HEAD plus clean working tree before and after each fixture build or validation operation.
2. An explicit `-BuildD31RecoverySeeder` option may build the D31 test helper using only this fixed command and feature, with the target directory beneath the caller-selected external output root:

   ```text
   cargo build --quiet --locked --manifest-path <candidate>\vita-agent\Cargo.toml --bin vita-agent --features d29-h9-test-helper --target-dir <external-output-root>\d31-recovery-seeder-target
   ```

   The expected output is `<external-output-root>\d31-recovery-seeder-target\debug\vita-agent.exe`. A sibling `d31-recovery-seeder-build.json` records schema version 2, the exact candidate SHA, fixed command/feature, canonical manifest/target/artifact paths, caller-pinned toolchain profile and exact locked-fetch provenance, PowerShell/Cargo process identities, exit status, and artifact bytes, SHA-256, and file identity. The D31 real-process test independently validates that record and reopens/rechecks the helper image before and after spawn; schema version 1 is rejected.
3. Fixture manifest schema v3 remains unchanged. Existing fixture semantics remain unchanged except that Git trust failures now fail closed. Host retained-handle checks remain the final security authority.

#### Frozen invariants

1. No production authority, protocol, persistent schema, identity-continuity, grant/revoke, recovery-atomicity, or security-boundary semantics are changed.
2. The external helper build and its record are test evidence only; they do not become an installer input or production sidecar.

#### Allowed implementation space

- Add the pinned-Git trust checks and sanitized Git invocation environment to the D32 fixture producer and consumer.
- Add the opt-in D31 recovery seeder producer and its external build record/validation used by the D31 real-process test.
- Add focused negative tests for wrong/missing Git path or hash, unsafe inherited Git configuration, dirty or changed candidate state, and changed/missing seeder artifacts or records.

#### Forbidden implementation

- Do not change fixture manifest schema v3, existing fixture build semantics, Host retained-handle authority, production migrations, external/frozen protocols, sidecar CLI, Tauri shipping resources, or installer/package behavior.
- Do not allow the D31 helper image to enter the shipping release bundle or Tauri runtime resource map.

#### Required tests

- Verify caller-pinned Git path/hash enforcement and sanitized Git environment/configuration for both fixture production and consumption.
- Verify exact HEAD and clean-tree checks before and after fixture builds.
- Verify the D31 seeder is opt-in, runs only the fixed locked Cargo command/feature into an external target, and emits a record whose candidate, command, paths, exit status, bytes, hash, and identity validate independently.
- Verify missing, stale, altered, or reparse-backed helper artifacts/records fail closed; retain the real-process D31 test as the required consumer.

#### Required real canary

- This decision closes no D31 real-process or D32 Host canary. The D31 helper must be consumed by its real-process test; all D32 ordered real Host modes and negative evidence remain mandatory.

#### Required negative evidence

- Missing or mismatched pinned Git executable, inherited Git environment/configuration, changed HEAD, dirty tree, failed fixed build, missing or modified seeder record, wrong helper path, changed helper bytes, and stale helper file identity must be rejected.

#### Compatibility constraints

- Fixture schema remains version 3 and existing fixture semantics remain unchanged except fail-closed trust handling.
- No production migration, protocol, sidecar CLI, Tauri resource-map, or installer/package change is authorized.

#### Escalation triggers

- Any need to change Host retained-handle authority, fixture schema, production protocol, persistent schema, sidecar CLI, or shipping resource mapping requires Sol arbitration before implementation.

#### Supersedes / Superseded by

- Supersedes none. This decision is independent of ADR-D32-EVIDENCE-BUNDLE-V1 and does not grant D32 freeze authority.

---

### ADR-D32-RELEASE-EVIDENCE-BOOTSTRAP — D32-A Release Evidence Bundle 两阶段 Bootstrap

**Status:** APPROVED WITH CONDITIONS
**Decision authority:** GPT-6 Sol
**Decision date:** 2026-09-23
**Related milestone:** D32-A final-gate evidence
**Related baseline:** `7923794565f6742fbfd760c2f3b01e9dd18abd42` (D32 stage base); repair-lineage base: `4c727ec5ba42e0288400d5847b43b08a1c96bc54`

#### Context

Protocol §16.1.5 requires verified bundle hashes before an expensive build or real canary. ADR-D32-EVIDENCE-BUNDLE-V1 defines two fixed release Cargo commands as the evidence-producing step that creates the exact-candidate artifacts, manifest, and attestation whose hashes must be verified. This decision resolves only that initial bootstrap ordering; it does not weaken or replace the full aggregate gate.

#### Decision

1. **Phase 0 — before the first evidence-producing release build:** Record that applicable governance is current; the exact candidate SHA is established and the working tree is clean; the full affected local matrix is complete, including provider/tool two-turn and mode/cleanup contracts; the fixed commands and provenance schema/canonical-path specification are validated; and the external evidence output path is fresh, absolute, outside and non-overlapping with the clone, and will not overwrite existing data. Record `bundle hashes = PENDING`, not PASS. Do not run a real canary or claim the §16.1.5 aggregate has passed.
2. **Phase 1 — constrained bundle production and gate resumption:** Only after Phase 0 passes, the D32 preflight attestor may run exactly the two fixed locked release Cargo commands in ADR-D32-EVIDENCE-BUNDLE-V1, on the same exact clean candidate, to create its three artifacts, manifest, and sibling attestation. Do not reuse stale target outputs or substitute mocks, fixtures, or evidence for a prior candidate as proof of this run. Any command, process/tool/artifact identity, or before/after SHA/clean-state failure is `BLOCKED`. Immediately validate the generated evidence's exact schema, SHA binding, hashes, byte counts, file identities, fixed paths/commands, flat-only contents, `runtime_resources = []`, Tauri shipping resource map, and clean candidate state. Then repeat the full §16.1.5 aggregate check with `bundle hashes = VERIFIED`. No subsequent expensive gate or real canary may start until that full aggregate passes.

This is a narrowly scoped bootstrap exception for those two evidence-producing commands only. It does not authorize any other build before the full aggregate, does not satisfy or waive any real-canary mode or negative evidence, and does not confer freeze authority. If any Phase 0 condition is missing, no bootstrap build is authorized.

#### Frozen invariants

1. The general §16.1.5 rule remains controlling except for the exact ordering above; all full-evidence requirements remain mandatory before downstream expensive gates or real canary.
2. No product behavior, production code, protocol, persistent schema, Host authority, real-canary requirement, Tauri shipping configuration, or installer/package behavior changes are authorized.
3. A Phase 0 `PENDING` value is an explicit staged state, never a PASS or substitute for final verified bundle hashes.

#### Allowed implementation space

- Clarify protocol §16.1.5 and the AGENTS.md gate mirror to state this exact two-phase sequence and authority ordering.
- Follow the existing D32 evidence attestor/validator contract without changing its fixed commands or bundle schema.

#### Forbidden implementation

- No reuse of stale/pre-existing target outputs as proof of the fixed commands, prior-candidate bundle, mock, or fixture substitution.
- No expansion to other release/build commands, candidate SHAs, evidence bundles, tasks, or real canaries.
- No relaxation of the complete post-bundle aggregate, required real canary, negative evidence, or HIGH freeze sequence.

#### Required evidence

- Preserve Phase 0 records and mark bundle hashes `PENDING` until the attestor has completed successfully.
- Record exact candidate SHA and clean state before and after each fixed command; bind completion/exit/process identity and artifact path/bytes/hash/file identity as required by ADR-D32-EVIDENCE-BUNDLE-V1.
- Immediately validate the created manifest and attestation together and record the subsequent full §16.1.5 aggregate with bundle hashes `VERIFIED` before downstream expensive gates or real canary.

#### Supersedes / Superseded by

- Supersedes none. This ADR resolves only initial D32-A evidence-bundle bootstrap ordering and does not supersede ADR-D32-EVIDENCE-BUNDLE-V1, D32-A gates, or Sol final-freeze authority.

---

### ADR-D32-PHASE0-TOOLCHAIN-PROFILE — D32 Phase 0 本地矩阵与 Caller-Pinned Build Toolchain

**Status:** APPROVED WITH CONDITIONS
**Decision authority:** GPT-6 Sol
**Decision date:** 2026-09-23
**Related milestone:** D32-A final-gate evidence
**Related decisions:** ADR-D32-EVIDENCE-BUNDLE-V1; ADR-D32-RELEASE-EVIDENCE-BOOTSTRAP; ADR-D32-FIXTURE-TRUST-D31-SEEDER

#### Context

The bootstrap exception requires a trustworthy Phase 0 matrix before the two release commands, but no fixed runner or build-tool authority previously existed. Ambient PATH, rustup selection, Cargo configuration, and inherited build environment are not adequate provenance. The local matrix is necessary preparation evidence; it is not a substitute for release artifacts, D31 real-process tests, provider-backed evidence, hardware evidence, or the post-bundle aggregate.

#### Decision

1. **Phase 0 authority and order.** A code-owned `scripts/d32-phase0-matrix.ps1` runner performs, in order: the existing five D32 fixture build phases; the full `vita-agent-protocol` local suite; the full Vita local suite; and the full Host local suite. Phase 0 permits those locked local fixture/test compilations only; it permits no release build, D31 real-process seeder, real provider request, hardware capture, or Host real canary. Phase 0 records `bundle hashes = PENDING` and is not a §16.1.5 aggregate PASS. The ten D31 real-process test cases listed below are explicitly `NOT RUN` in Phase 0 and remain mandatory after validated bundle plus full post-bundle aggregate. The four source-ignored D29G2 real-provider tests remain `NOT RUN` pending post-bundle evaluation with the user-authorized provider. The three source-ignored interactive/physical capture tests remain `N/A — NOT RUN` with that reason. None is counted as PASS.
2. **Fixed local package commands.** Before test execution, the runner records `--list` and `--ignored --list` output for each package and requires the fixed test inventory, exact names/counts of ignored tests, and unique presence of every deferred D31 test. Any missing/duplicate deferred name or any new/unapproved ignored/skipped test is `BLOCKED`, before Phase 1. The test commands use Cargo's default test parallelism; no global `--test-threads=1` is allowed:
   ```text
   cargo test --manifest-path vita-agent-protocol/Cargo.toml --all-targets --locked --offline
   cargo test --manifest-path vita-agent/Cargo.toml --all-targets --locked --offline --features d32-a-test-helper -- <one --skip for d31_c_real_process_crash_recovery_canary>
   cargo test --manifest-path src-tauri/Cargo.toml --all-targets --locked --offline --features d32-a-host-canary -- <one --skip for each of the nine Host D31 real-process names>
   ```
   Each skip is admitted only after the exact test name has been found uniquely by `--list`; test summaries must account for the exact skip count. A fixed focused local selection additionally runs these exact test suffixes, each uniquely resolved from `--list` and invoked with `--exact` (full module-qualified names are captured in the record): Vita `provider_gateway::tests::d32_native_responses_two_round_golden_and_pairing_are_exact`, `provider_gateway::tests::d32_second_turn_omits_forced_tool_choice`, `sidecar::tests::d32_forced_tool_latch_requires_exact_two_round_contract`, `d32a::tests::d32_vita_failure_preserves_primary_and_secondary_cleanup`; Host `vita_sidecar::tests::d32_each_host_mode_has_uniform_missing_provider_preflight`, `vita_sidecar::tests::d32_all_eight_modes_satisfy_the_pure_trace_contract`, `vita_sidecar::tests::d32_cancel_worker_completion_covers_return_panic_and_scope_cleanup`, `vita_sidecar::tests::d32_cancel_worker_hang_is_bounded_without_detach_and_can_cleanup`, `vita_sidecar::tests::d32_a_same_valid_host_grant_replay_is_denied`, and `vita_sidecar::tests::d32_cargo_binding_requires_the_fixed_non_git_marker`. These focused tests run in addition to, not instead of, the full package suites.
3. **Explicit D31 real-process deferral.** The exact ten deferred names are `d31_c_real_process_crash_recovery_canary` (Vita), `d31_c_real_process_workspace_replace_canary`, `d31_c_real_process_workspace_replace_revocation_canary`, `d31_d_real_process_workspace_patch_canary`, `d31_d_real_process_workspace_patch_conflict_canary`, `d31_d_real_process_workspace_patch_revocation_canary`, `d31_c_real_process_recovery_canary`, `d31_c_real_process_recovery_revocation_canary`, `d31_b_real_process_workspace_read_canary`, and `d31_b_real_process_workspace_read_revocation_canary` (Host). Each is represented as `NOT RUN — deferred until validated bundle and full aggregate`, never silently skipped or passed. Their real-process evidence remains mandatory in the later D31 phase.
4. **Runner-owned evidence.** The runner itself captures exact argv/cwd, complete bounded stdout/stderr logs and hashes/bytes, exit codes, test result counts, exact ignored/skipped names and counts, required named-test outcomes, tool/process identities, exact candidate HEAD and clean status before/after every command, profile/lock input hashes, and process-tree cleanup. A caller-authored PASS field is invalid. Any command failure, log/inventory parse ambiguity, unapproved ignored/skip, output mutation, unknown child image, or unverified process cleanup is `BLOCKED`. To preserve the strict fixture manifest v3 consumer contract, toolchain/fetch provenance is stored in the fixed external sibling `fixture-build-provenance.json` (`D32_FIXTURE_BUILD_PROVENANCE_V1`), which binds the manifest's bytes/SHA/opened-handle ID, profile/run fields, and each exact locked fetch command, status, and Cargo process identity; the fixture manifest's six original environment fields remain unchanged. The Phase 0 record binds the external run root, unique populated Cargo home, fetch evidence, and exact ordered fixture/fetch stdout/stderr log references with their hashes/bytes/opened-handle identities, as well as the profile SHA and exact candidate SHA. `GenerateBundle` must validate that record and its independently supplied SHA before running either fixed release command. `ValidateOnly` reports artifact-only validation unless a separately validated full-aggregate record is explicitly supplied; this decision does not authorize representing artifact validation as a gate PASS.
5. **Toolchain profile.** Release/Phase 0 tooling requires an external caller-provided absolute profile path plus an independently supplied expected SHA-256. The duplicate-key-free exact schema is `D32_BUILD_TOOLCHAIN_PROFILE_V1` schema 1 with: fixed `x86_64-pc-windows-msvc` target; separate canonical `powershell_root`, `rust_toolchain_root`, and finite `native_roots[]`; exact current `pwsh.exe` host-process identity plus direct Cargo, rustc, and rustdoc identities; exact executable inventories for the Rust `bin` and native PATH entries; canonical native PATH/INCLUDE/LIB/LIBPATH directories under an approved native root; finite native MSVC/SDK executable identities (core `cl.exe`, `link.exe`, `lib.exe`, `rc.exe`, `mt.exe`, and any extra executable with an explicit reason); a code-owned exact allowlist of native directory/version environment variables; and exact manifest/Cargo.lock path+SHA-256 entries. Each executable identity records absolute path, SHA-256, bytes, and opened-handle volume serial/file ID. Current PowerShell `Process.MainModule` path/hash/file identity must match the profile before and after the run; the PowerShell host is recorded but excluded from child PATH. Direct Cargo/Rust tools must be beneath the Rust toolchain root, not PATH/rustup shims, and target-triple probing must match the fixed target. Every executable in constructed PATH must be pinned or observed and verified; batch launch is rejected unless a separately approved/pinned execution path is implemented. Tool identities, exact profile SHA, and effective nonsecret environment policy are checked and recorded before and after evidence phases.
6. **Controlled environment and Cargo home.** Each Phase 0 run creates one unique, empty, external `CARGO_HOME`; user caches/config/credentials are never copied. A pinned direct Cargo performs locked fetches for the exact profile-bound manifests before local tests, without inherited credentials, proxy, wrapper, Cargo/Rust/Rustup/Git configuration, or ambient PATH. The runner rejects discovered Cargo configuration files along the working-directory ancestry and in the fresh home; `CARGO_NET_GIT_FETCH_WITH_CLI` and external Git/SSH/credential helpers are not admitted. Locked `git+` sources are allowed only when `Cargo.lock` contains a full immutable 40-hex commit object ID (and `rev=` agrees where present), and the exact lock SHA is bound in the profile/record. Cargo's in-process libgit2 may fetch those locked sources; no Git CLI, SSH helper, credential helper, proxy, or unapproved child image may execute. If fetching requires external help, auth, or a proxy, it is `BLOCKED`; do not silently enable one. After fetch, it sets `CARGO_NET_OFFLINE=true` for fixtures, tests, and the two fixed release commands. The populated Cargo home is bound by the Phase 0 record and revalidated by release generation; it is not required to be empty again. This records an allowlisted environment and toolchain profile, not a hermetic-build claim. D31 seeder creation uses the same profile schema and verifier but its own fresh home/fetch record after the bundle and full aggregate; its fixed command argv is unchanged.
7. **Fresh-output handling.** Fixture manifest schema v3 and its fixed repository `target/debug` paths remain unchanged; the separate Phase 0 provenance sidecar does not expand or replace that consumer wire schema. To establish freshness, only the exact five fixture output files may be moved to a unique external recoverable quarantine after literal, non-reparse, opened-handle identity/hash validation and an exact move-result recheck; no broad deletion or directory move is allowed. The three fixed release outputs must be absent and freshly produced by the fixed Phase 1 commands; they are never quarantined or reused.

#### Frozen invariants

1. No production behavior, persisted product schema, protocol, Host authority, Tauri shipping resource map, installer/package behavior, or fixture manifest v3 semantics change.
2. Host retained-handle checks remain the final security authority; PowerShell build provenance does not replace them.
3. Phase 0 closes only its declared local matrix. D31 real-process, D29G2 real-provider, physical capture, all D32 ordered real Host modes, negative evidence, and final freeze requirements remain outstanding until separately evidenced.

#### Allowed implementation space

- Implement the fixed Phase 0 runner and strict profile/record verification in `scripts/d32-phase0-matrix.ps1` and `scripts/d32-preflight.ps1`.
- Add only the required Phase 0/profile/provenance schema fields with explicit version bumps and reject prior/unknown versions. Fixture manifest schema v3 remains unchanged.
- Clarify the Phase 0 ordering in protocol §16.1.5 and its AGENTS.md mirror.

#### Forbidden implementation

- No ambient toolchain resolution, PATH fallback, rustup shim/override selection, inherited Cargo/Rust/Git/proxy/credential/wrapper/config variables, or caller-authored test PASS.
- No external provider request, D31 real-process execution/seeder build, screen capture, or Host real canary in Phase 0.
- No serializing the full test suite, broad target deletion/quarantine, reuse of prior candidate evidence, or hermetic-build claim.
- No change to fixed release command argv or fixed D31 seeder command argv.

#### Required tests and evidence

- PowerShell SelfTest covers exact profile/Phase 0 schemas, duplicate/extra/missing/wrong-type values, pinned tool hash/bytes/handle-ID mismatch, PATH inventory additions/missing files, stale lock hashes and immutable Git lock pins, wrong target profile, missing/extra/duplicated test/skip/ignored names, new unapproved ignores, incorrect test counts, stale Phase 0 SHA/profile/lock bindings, log hash mismatch, non-clean pre/post state, and unknown child image (including attempts to expose Git CLI/SSH/credential helpers through PATH).
- Operational Phase 0 logs and record are tied to the exact candidate and caller-pinned profile. If actual `--list` differs from this ADR's fixed inventory, stop before any release command and return the mismatch for architecture review.
- After bundle generation, rerun the full §16.1.5 aggregate with `bundle hashes = VERIFIED`; only then schedule D31/D29 real evidence and later real canary gates.

#### Supersedes / Superseded by

- Supersedes only conflicting implementation detail in ADR-D32-RELEASE-EVIDENCE-BOOTSTRAP where necessary to permit the declared Phase 0 local fixture/test compilation. It does not expand Phase 1 beyond the two fixed release commands, alter the bundle manifest schema, or relax any downstream gate.

#### Approved schema supersession clarification (2026-09-24)

The V1 profile identifier and field list above are retained as historical decision text. Under the later approved ADR-D32-PROCESS-EVENT-TRACE-V1 strict-migration decision and its V2 continuation, the current caller-pinned profile wire is exactly `D32_BUILD_TOOLCHAIN_PROFILE_V2` schema 2. It requires `native.path_scripts` (identity pins for every dormant `.bat`/`.cmd` in the constructed Rust/native PATH) and top-level `windows_child_images` (the exact pinned System32 `conhost.exe` image); V1 or unknown/missing/extra-field profiles are rejected. The D31 recovery seeder producer and Host consumer use this same V2 schema and verifier. This clarification supersedes only the historical profile wire version/field list above; it does not change D31 seeder argv, the caller-pinned profile path/SHA binding, process-parent identity checks, or any Host/build authority.

### ADR-D32-PROCESS-EVENT-TRACE-V1 — D32 Phase0/Release Evidence Batch Execution Boundary

- **Status:** SUPERSEDED
- **Decision authority:** GPT-6 Sol Max
- **Decision date:** 2026-09-24
- **Related milestone:** D32-A final-gate evidence
- **Related decisions:** ADR-D32-PHASE0-TOOLCHAIN-PROFILE, ADR-D32-EVIDENCE-BUNDLE-V1

#### Context

The installed Rust toolchain and the only complete Windows SDK x64 tool directory contain dormant `.cmd` files. Their presence is distinct from launching a command processor, but the existing profile inventory rejects any such file before it inventories executable images. The existing Phase0 descendant check samples CIM process state after resume and cannot prove that a short-lived process was never started or that a trace had no lost events.

#### Decision

1. **Dormant scripts do not grant launch authority.** The caller-pinned Rust, MSVC, and Windows SDK constructed PATH directories may contain dormant `.bat`/`.cmd` files. Each such resident script must be recorded with its canonical absolute path, byte count, SHA-256, and opened-handle volume serial/file ID, and those identities must be revalidated at the required evidence boundaries. This is not permission to execute a script, command processor, or shell.
2. **Complete OS process events are required.** A Phase0 or release-evidence PASS requires a lossless OS process start/exit event stream beginning before the first pinned Cargo invocation and continuing until each associated Job Object has been confirmed to contain zero active processes. The evidence must bind exact parent lineage, non-recycled process identity, canonical image path and opened-handle image identity, plus the trace source’s event/buffer loss counters. It must cover locked fetches, all five fixture phases, Phase0 suites/focused tests, and both fixed release builds. CIM polling is not an acceptable source or fallback.
3. **Fail closed on any ambiguity or prohibited launch.** Any missing start/exit event, nonzero loss counter, unknown or ambiguous parent chain, PID reuse not disambiguated by a non-recycled process key, image path/identity mismatch, or launch of `cmd.exe`, another command processor, a `.bat`/`.cmd` script, Git/SSH/credential helper, or other unapproved image makes the evidence `BLOCKED`. A trace source that cannot establish complete coverage is not PASS evidence.
4. **Negative evidence is mandatory.** The implementation must test fast-exit command-processor launches; `.cmd` invocation by PATH resolution and absolute path; unknown child/helper images; PID reuse and ambiguous ancestry; trace loss and missing events; resident dormant-script acceptance; resident script/executable identity tampering; and the normal pinned toolchain/build/test child processes. These tests do not authorize a production Host sandbox change.
5. **No host-policy or tool-image workaround.** Do not change OS audit policy, ETW permissions/ACLs, user/group privileges, or other host configuration. Do not copy or mirror installed tool images to avoid resident scripts. Candidate source/build inputs remain an explicit trust premise; the production D32 Host sandbox authority is unchanged.
6. **Strict evidence-schema migration.** Any profile, fixture-provenance, Phase0 record, release attestation, or aggregate record whose exact fields or validation meaning changes must receive an explicit schema/type version bump. Validators and SelfTests must reject the previous/unknown versions; evidence from prior candidates or old schemas cannot inherit PASS.
7. **Controlled profile candidate creation.** A code-owned generator may emit a profile candidate only to a new external path and must refuse overwrite. Generation does not authorize use: the Coordinator independently reviews and supplies the exact expected profile SHA-256 to the evidence runner.

#### Frozen invariants

1. Dormant script presence is allowed only when its file identity is caller-pinned and current; script or command-processor execution remains prohibited.
2. An incomplete or lossy process event source is missing required evidence and therefore `BLOCKED`.
3. No changes are made to production Host sandbox authority, product behavior, manifest v3 semantics, or fixed command argv.

#### Allowed implementation space

- Update D32 profile, Phase0, fixture-provenance, release-attestation, and aggregate tooling only as required to represent pinned resident scripts and complete process event evidence.
- Add an external create-new profile candidate generator whose output requires independent caller pinning.
- Apply strict version bumps and old-version rejection to all affected records.

#### Forbidden implementation

- No 150ms CIM polling fallback or best-effort/loss-tolerant process trace.
- No execution allowance for `.bat`/`.cmd`, `cmd.exe`, shells, Git/SSH/credential helpers, or other unapproved images.
- No OS policy/ACL/group/privilege changes and no copied/mirrored toolchain images.
- No change to production D32 Host sandbox authority or fixed Cargo argv.

#### Required tests and evidence

- Negative coverage listed in Decision 4, with exact trace start/stop/loss counters and parent/non-recycled process identities.
- Exact profile/script identity tests, strict schema/version tests rejecting all previous record versions, and exact-SHA runner evidence.
- If a complete supported process event source is unavailable without host-policy changes, report `BLOCKED_ARCHITECTURE`; do not run Phase0/release evidence or claim PASS.

#### Supersedes / Superseded by

- Clarifies the dormant-script and process-launch meaning of ADR-D32-PHASE0-TOOLCHAIN-PROFILE. It adds a required process-event evidence boundary; it does not authorize any batch/command-processor launch or alter downstream D32 gates.
- The trace-source condition in this historical V1 decision is superseded by ADR-D32-PROCESS-EVENT-TRACE-V2. Its dormant-script identity rule, launch denials, negative evidence, no-policy-change rule, and downstream-gate limits remain in force.

### ADR-D32-PROCESS-EVENT-TRACE-V2 — Synchronous Win32 Debug Events and Independent Job Accounting

- **Status:** APPROVED
- **Decision authority:** GPT-6 Sol Max
- **Decision date:** 2026-09-24
- **Related milestone:** D32-A final-gate evidence
- **Related decisions:** ADR-D32-PHASE0-TOOLCHAIN-PROFILE, ADR-D32-EVIDENCE-BUNDLE-V1, ADR-D32-PROCESS-EVENT-TRACE-V1

#### Context

The approved V1 boundary correctly prohibited command-processor execution, polling fallback, host-policy changes, and copied tool images, but its requirement for a loss-counter-bearing OS event source was stricter than necessary. A bounded same-user Windows prototype established that `CreateProcessW(DEBUG_PROCESS|CREATE_SUSPENDED)`, synchronous `WaitForDebugEvent` processing, and a non-breakaway Job can gate the initial image before user code and independently reconcile process events against Job accounting without ETW or elevation.

The 2026-09-24 feasibility prototype was run as the ordinary user on candidate `24f93c6b776988cb935aedb6527834fa943fed1f`. Fast `cmd.exe`, PATH-resolved `.cmd`, absolute `.cmd`, an unpinned PowerShell helper, executable-byte mutation, and injected debug-chain interruption were all blocked; marker files remained absent. A pinned offline Cargo check completed with 7 CREATE / 7 EXIT events and Job total/active counts 7/0. Synthetic ledger negatives rejected overlapping PID reuse, missing exit, mismatched exit identity, ambiguous parent, and dropped-exit accounting. The dormant `.cmd` was allowed as inventory-only, while its byte mutation changed its SHA. This is feasibility evidence only, not Phase 0, release-build, canary, or gate evidence.

#### Decision

1. **Use synchronous Win32 debug events for each fixed Cargo root.** The existing fixed Cargo executable and argv remain caller-pinned. Start it with `CreateProcessW(DEBUG_PROCESS|CREATE_SUSPENDED)` inside a Job configured with `KILL_ON_JOB_CLOSE` and without breakaway allowance. The runner must retain process handles so the PID/creation identity cannot be recycled while its events are reconciled.
2. **Verify before continuation.** For every `CREATE_PROCESS_DEBUG_EVENT`, require a valid image file handle; obtain the canonical final image path, volume/file ID, bytes, and SHA-256 from the opened image handle; bind exact parent PID and retained parent creation identity; and validate the approved root/toolchain/Windows image or candidate-owned target-image classification before `ContinueDebugEvent`. Any null/invalid image handle, path/identity mismatch, unknown parent, duplicate/overlapping identity, or unapproved image blocks and terminates the owned Job before the event is continued. Reconcile every process EXIT event with the retained live identity.
3. **Close with independent Job accounting.** Evidence is acceptable only when the synchronous debug chain closes without API errors/interruption, every CREATE has exactly one matching EXIT, all image identities are approved, `Job.TotalProcesses` equals unique CREATE count, and `Job.ActiveProcesses` is verified as zero. Win32 debug events have no ETW-style loss counter; exact event/identity accounting plus the independent Job counters are the required completeness proof. There is no CIM polling or other fallback.
4. **Fail closed on uncertainty or prohibited launch.** Unknown/ambiguous parentage, PID reuse ambiguity, missing/duplicate event, missing EXIT, mismatched process handle/event identity, null `hFile`, debug-chain interruption, Job escape/count mismatch, unknown image, or launch of `cmd.exe`, another command processor, `.bat`/`.cmd`, shells, Git/SSH/credential helpers, or other unapproved executable means BLOCKED. No command processor or script is granted launch authority.
5. **Dormant script policy is unchanged.** Canonical path, bytes, SHA-256, opened-handle volume serial/file ID are pinned for resident `.bat`/`.cmd` entries and revalidated. Their presence grants no invocation permission. Pinned direct Rust/MSVC/SDK directories remain allowed; tool images are not copied or mirrored.
6. **Keep the trust boundary and downstream requirements unchanged.** This decision changes only the D32 Phase 0/release-evidence harness. It does not change production Host sandbox authority, frozen product/protocol/authority semantics, source/build-input trust premise, OS policy/ACL/privileges, fixed Cargo argv, manifest v3, shipping resources, required D32 gates, or formal independent gate.
7. **Use strict schema migration and create-new profile generation.** Bump and reject previous/unknown versions for affected records: profile V2, fixture build provenance V2, Phase0 record V2, release build attestation V3, post-bundle aggregate record V2, and synchronized debug/Job process trace V2. Fixture manifest v3 remains unchanged. The profile candidate generator may write only a new external file, refuses overwrite, copies no images, and emits no use authorization; the Coordinator independently reviews and pins its exact SHA-256.

#### Frozen invariants

1. `WaitForDebugEvent` synchronous event handling plus exact process identities and independent Job accounting is the only accepted D32 Phase 0/release process-trace source under this decision; incomplete evidence is BLOCKED.
2. Image validation precedes `ContinueDebugEvent`; handles stay retained through EXIT; all launched process images and parent identities must reconcile exactly.
3. No process-launch permission is granted to dormant scripts or command processors, and production Host authority is unchanged.

#### Allowed implementation space

- Implement the synchronized trace and Job accounting in D32 PowerShell/native launcher tooling, with exact versioned records and validator coverage.
- Add an external create-new profile-candidate generator and identity-revalidation logic for resident dormant scripts and Windows child images.
- Run bounded ordinary-user feasibility checks and D32-specific negative tests without changing host policy or installation files.

#### Forbidden implementation

- No ETW/CIM fallback, best-effort event-loss tolerance, or reporting a missing/incomplete event source as PASS.
- No OS audit policy, ACL, privilege, group, security-policy, or machine configuration changes.
- No copied/mirrored Rust, MSVC, SDK, or Windows executable images; no `.bat`/`.cmd`, command processor, shell, Git/SSH/credential helper launch permission.
- No production Host sandbox authority change, no fixed argv change, and no claim that focused tests equal Phase 0, release, canary, or stage PASS.

#### Required tests and evidence

- Negative evidence must cover fast-exit command processors, PATH and absolute `.cmd`, unknown child/helper, PID reuse and ambiguous ancestry, missing CREATE/EXIT and debug-chain interruption, Job accounting mismatch, dormant-script acceptance plus script/image mutation, and normal pinned Cargo/toolchain/build/test descendants.
- Exact profile, fixture provenance, Phase0, release attestation, and aggregate schema tests must reject each previous version and unknown fields/types. Evidence must bind exact candidate SHA and the Coordinator-pinned profile SHA.
- Phase 0 must cover all three locked fetches, all five fixture phases, required Phase0 suites/focused tests, and both fixed release builds; it remains blocked if any event/accounting/image/parent check is missing.

#### Required real canary

- This decision closes no D32 real Host canary or downstream gate. All previously required ordered real Host modes, negative evidence, independent Luna High review, and stage closure remain outstanding until separately evidenced.

#### Required negative evidence

- Null/unknown image handle, image path/hash/file-ID tamper, unknown helper, root parent PID mismatch, unknown or ambiguous parent, overlapping PID reuse, missing/mismatched EXIT, event-chain interruption, Job escape/account mismatch, forbidden command-processor/script/Git/SSH/credential-helper launch, and stale dormant script identity must block.

#### Compatibility constraints

- Keep the root governance protocol v1.1 role boundaries, exact-SHA gate binding, single Build Owner, no-worktree rule, no-push default, no-`cargo clean`, and Coordinator-owned profile pin. Preserve the historical V1 ADR and other approved D32 ADRs; this V2 supersedes only the V1 trace-source condition.

#### Escalation triggers

- If current-user debug-event delivery, pre-continuation image-handle verification, or independent Job accounting cannot be established, stop Phase 0/release evidence as BLOCKED_ARCHITECTURE; do not weaken this decision or change OS policy.

#### Supersedes / Superseded by

- Supersedes only V1's loss-counter-bearing trace-source requirement. All V1 launch-denial, dormant-script, no-policy-change, no-image-copy, and no-downstream-gate relaxations remain operative unless explicitly changed by a later architecture decision.

#### Approved dedicated-thread and abort-cleanup clarification (2026-09-24)

This clarification is approved under ADR-D32-PROCESS-EVENT-TRACE-V2 and retains the V2 process-trace record contract; it does not authorize a trace V3 record or alter production Host authority.

1. `CreateProcessW`, `WaitForDebugEvent`, and `ContinueDebugEvent` for each fixed Cargo root run on one dedicated, joinable debugger OS thread. After the debug connection is established, that thread must successfully call `DebugSetProcessKillOnExit(TRUE)` before resuming the root with `ResumeThread`.
2. On any image/identity validation, debug API, timeout, missing-EXIT, or other event-chain failure, evidence is BLOCKED. Terminate the owned Job through a retained Job handle; the debugger thread exits without continuing an unvalidated CREATE event and is joined. Never call `DebugActiveProcessStop` and never Continue an unvalidated CREATE event.
3. Cleanup succeeds only after the debugger thread has exited and joined within its bound, every independently retained process handle is signaled, the Job's active-process count is independently verified as zero, and the debugger association is verified absent where queryable. Then close the retained Job, `PROCESS_INFORMATION`, `OpenProcess`, duplicate root, and other owned handles. A successful termination call or Job ActiveProcesses=0 by itself is not cleanup proof. Event-owned CREATE/CREATE_THREAD process and thread handles are not manually closed; matching continued EXIT events retire them. Explicitly debugger-owned image-file handles are closed by the debugger.
4. A completed trace still requires every CREATE image and parent identity to be validated before continuation; CREATE and EXIT identities reconcile exactly, Job total equals unique CREATE count, and Job active count is zero. On blocked CREATE paths, record zero Continue calls for the offending CREATE and establish no user-code marker, joined debugger thread, signaled retained process handles, zero Job active count, and no remaining debugger association/orphan.
5. Same-user runtime negative evidence covers root PID mismatch, null image handle, unknown image/parent/helper, forbidden command processor and PATH/absolute script launches, debug-chain interruption, Wait/Continue error or timeout, missing EXIT, and rapid spawn/exit/PID-reuse races. Normal pinned toolchain/build/test descendants must remain accepted. Any missing cleanup or identity proof is BLOCKED; no polling or policy fallback is allowed.

---

### ADR-D32-GOVERNANCE-V12-RECONCILIATION — D32 Governance v1.2 与前瞻 Stage Contract

**Status:** APPROVED WITH CONDITIONS
**Decision authority:** GPT-6 Sol Max
**Decision date:** 2026-09-27
**Related milestone:** D32 final-gate readiness（D32-A-R2）
**Related baseline:** e902a05bf3193212c131c78ec7dfe6b72e2c292f

#### Context

候选树的治理入口与通用 protocol 仍为 v1.1，用户当前治理已更新为 v1.2。候选树还保留 D32 已批准的 §16.1.1–§16.1.5 聚合门槛和 release-evidence bootstrap 顺序；它们继续约束 D32，且 §16.1.5 的 Phase 0 → Phase 1 次序是唯一窄例外。候选的既有 ADR、F-01 至 F-17 与历史 exact-SHA 证据属于已批准历史，不能用空白索引或新文档覆盖。

#### Decision

1. 当前 AGENTS.md v1.2 与 CODEX_DEVELOPMENT_PROTOCOL.md v1.2 现在控制 Coordinator、Worker、workspace、Integration/Build Owner、gate 和 Git 的通用治理。角色职责优先于模型名称；本决定不改变已配置角色或职责边界。
2. 候选原有完整 D32 §16.1.1–§16.1.5 补充协议继续有效。保留每条门槛、证据要求、禁止项和稳定的 §16.1.5 引用；Phase 0 → Phase 1 例外严格限于该补充协议及已批准 D32 ADR 所列的五个 fixture phases、完整本地测试矩阵和两条固定 locked release Cargo argv。该例外不扩展到其他候选、命令、build、real canary、D31 seeder、provider 请求或 gate。
3. 保留候选 ARCHITECTURE_DECISIONS.md 的所有既有决定、状态、历史证据和 FROZEN_INVARIANTS.md 的 F-01 至 F-17。只追加本决定，不替换或改写既有 ADR。ADR-D32-PROCESS-EVENT-TRACE-V2 对通用 protocol v1.1 的治理引用由当前 v1.2 取代；其中 no-worktree 的通用工作区规则依当前 v1.2 更新为受控 Patch Worktree + 唯一 Integration Tree。该历史 ADR 中 Phase 0 包含两条 release build 的概述，依后续批准的 ADR-D32-RELEASE-EVIDENCE-BOOTSTRAP、ADR-D32-EVIDENCE-BUNDLE-V1、ADR-D32-PHASE0-TOOLCHAIN-PROFILE 及本候选 §16.1.5 的精确定义，由 Phase 0 local fixture/test matrix → Phase 1 两条固定 release command 取代。以上仅澄清已批准的通用治理和 D32 Phase 0/Phase 1 次序；Win32 debug event、Job accounting、trace、schema、trust、negative-evidence 和 downstream gate 条件保持不变。
4. 建立独立记录 SC-D32-V1，自 2026-09-27 起前瞻生效，以 e902a05bf3193212c131c78ec7dfe6b72e2c292f 为 D32 Integration 起始基线。该建立日期不声称存在先前 ratification；基线也不代表任何 gate 已满足。Contract scope、required sequence 与 exit criteria 记录于 docs/governance/SC-D32-V1.md。
5. scripts/d32-fixture-prebuild.ps1 的 stdout/stderr log 必须只含被启动 child process 实际写入的原始字节。phase、exit code、captured PID、cleanup 和错误等 wrapper 状态保留在现有结构化 result、process trace 与 reap/cleanup 字段中，不得追加进 raw stream。该修复不更改任何证据 schema、trace source、信任边界、fixed Cargo argv、fixture manifest v3、production authority 或 negative/gate 要求。
6. raw stdout/stderr 字节及其 hashes/bytes 属于 Phase 0 provenance；新候选必须重新建立受影响的 fixture、Phase 0 和后续 exact-SHA 证据。既有候选的 gate 或 evidence 不继承。
7. D32 工作在 SC-D32-V1 定义的 Sol Max D32 closure 后停止；本决定不规划或建立 D33。

#### Frozen invariants

1. 用户当前指令和 AGENTS.md / protocol v1.2 控制通用角色、workspace 和 Integration 治理；既有 frozen product、authority、identity、security、schema、protocol 与 recovery invariant 不变。
2. D32 §16.1.1–§16.1.5 supplement 及其唯一 Phase 0 → Phase 1 窄例外保持原语义和下游要求。
3. raw child stdout/stderr 与结构化进程/cleanup evidence 分离；raw logs 不包含 Codex wrapper 追加的文本。
4. Gate 绑定同一 clean Integration Candidate exact SHA；evidence missing remains BLOCKED。

#### Allowed implementation space

- 在 D32 候选中同步当前 AGENTS.md / protocol v1.2，保留 D32 supplement 和 §16.1.5 引用，并记录 SC-D32-V1。
- 更新仍标注 protocol v1.1 的 D32 governance diagnostic 文案，不改变 validator inventory、字段、schema 或 gate 判定。
- 修复 fixture raw-stream capture，并加入 success、non-zero、timeout/descendant-cleanup 的 focused SelfTest。

#### Forbidden implementation

- 不得弱化或扩展 §16.1.5 Phase 0 → Phase 1 例外、固定 Cargo argv、fixture/test inventory、schema、trace、trust、authority、negative evidence、real canary 或 Luna High/Sol gate。
- 不得覆盖或重建既有 ADR/Frozen Invariants、修改 F-ID，或把旧 evidence 移植为新 SHA 的 PASS。
- 不得建立 D33 计划或 Stage Contract。

#### Required tests

- SelfTest 必须以无末尾换行的 child payload 验证成功与非零退出时 stdout/stderr 与实际字节完全一致；payload 要含看似 wrapper trailer 的文本，以证明 child 内容保留且 wrapper trailer 不追加。
- timeout + descendant cleanup SelfTest 必须验证 raw streams 完全一致，并验证 timeout status、root/descendant identity、reap 记录、Job cleanup 与零 residual descendant。
- v1.2 governance diagnostics 应保留当前模型路由引用；其余 D32 SelfTest 和现有 negative coverage 不得减少。

#### Required real canary

- 本决定不关闭任何 D31 real-process 或 D32 Host real canary。SC-D32-V1 要求的十个 D31 real-process cases、适用且用户已授权 provider 的 D29G2 tests、八个有序 Host modes 与 negative evidence 仍须分别建立。

#### Required negative evidence

- SelfTest 拒绝 raw stream 中出现任何 wrapper 添加的 exit、descendant、timeout、PID 或 kill-output 文本，同时保留 child 主动写出的相同样式文本。
- 所有既有 D32 unauthorized mutation、revoke/cancel/Life/migration、identity、environment、cleanup、trace 与 process-tree negative evidence 保持强制。

#### Compatibility constraints

- 当前通用治理以 v1.2 为准；D32 supplement、D32 process trace V2、fixed commands、bundle/schema、fixture manifest v3、Tauri resource map、Host retained-handle authority 和所有既有 frozen invariants 保持不变。
- 此决定本身既不建立 Phase 0/Phase 1 evidence，也不代表 aggregate、real-canary、Luna High、Sol closure 或 FROZEN。

#### Supersedes / Superseded by

- 取代 ADR-D32-PROCESS-EVENT-TRACE-V2 中过时的通用 root governance v1.1/no-worktree 规则，以及其被后续 D32 bootstrap/toolchain ADR 与 §16.1.5 supersede 的 Phase 0 release-build 排期概述；不取代该 ADR 的任何 trace-source、process launch、identity、cleanup、schema、trust、negative evidence 或 downstream gate requirement。
- 无 D33 Stage Contract。

### ADR-D32-PINNED-GIT-ROOT-IDENTITY — Caller-Pinned Direct Git Root Identity Under V2 Trace

**Status:** APPROVED WITH CONDITIONS
**Decision authority:** GPT-6 Sol Max
**Decision date:** 2026-09-27
**Related milestone:** D32 final-gate candidate
**Related baseline:** `e902a05bf3193212c131c78ec7dfe6b72e2c292f`
**Related decisions:** ADR-D32-PHASE0-TOOLCHAIN-PROFILE, ADR-D32-PROCESS-EVENT-TRACE-V2, ADR-D32-GOVERNANCE-V12-RECONCILIATION

#### Context

D32 fixture preflight obtains candidate identity and clean-tree metadata through local Git queries. The existing V2 debugger/Job mechanism can verify a fast process before continuing its initial image, while a post-exit `.NET Process` identity query cannot establish that a short-lived image was verified before execution. This decision authorizes only the exact direct Git root independently pinned by the Coordinator; it is not general Git or helper execution authority.

#### Decision

1. **Exact caller-pinned root.** For D32 fixture-tooling Git metadata queries, the only authorized root image is `E:\Program Files\Git\mingw64\bin\git.exe`, independently bound by the Coordinator from an opened-handle snapshot with SHA-256 `1f2ee2de971b6d0a7a13f053014998b66c22df47f30f1907a767346392eb8d78`, length `4238224` bytes, volume serial `749614a1961465c0`, and 128-bit file ID `4aff000000000b000000000000000000`. The canonical path must have no reparse component. The caller-supplied path/hash is not self-authorizing: the implementation must revalidate the exact path, SHA-256, bytes, volume serial, file ID, and native identity immediately before process creation and against the retained executable handle.
2. **V2 pre-continuation identity and accounting remain mandatory.** Launch the direct root only through the synchronous V2 Win32 debug-event and non-breakaway Job path. For every CREATE event, before `ContinueDebugEvent`, verify the opened image handle's canonical path, SHA-256, bytes, volume serial, and file ID, plus the exact parent PID and retained parent creation identity. Retain process handles through matching EXIT events; reconcile every CREATE/EXIT pair, Job total and active counts, debugger-thread join/exit, signaled handles, debugger association absence, and zero active Job processes. Fast exit does not waive any identity or cleanup check; uncertainty is BLOCKED.
3. **Narrow descendant rule.** The root is the only Git process. At most one optional direct child is permitted: the exact caller-pinned `conhost.exe` image from the V2 System32 Windows-image inventory. No wrapper, PATH-selected root, shell/command processor, second Git process, indirect descendant, or other child is authorized. Git/SSH/credential helpers remain hard-denied, including when launched by Cargo or any build/test process. The root exception must not change the generic V2 image-denial policy outside this dedicated caller-pinned Git capture.
4. **Fixed caller-owned use.** Git argv remains the exact code-owned metadata-query argv supplied by the fixture tooling; no arbitrary command, configuration override, trust, repository authority, schema, or protocol behavior is granted. Raw stdout/stderr capture, current fail-closed repository/metadata checks, toolchain-profile validation, and cleanup obligations remain in force.
5. **Required focused evidence.** Positive evidence covers fast successful direct-root `rev-parse`, `status`, and `ls-files` exits with complete V2 CREATE/EXIT and Job accounting. Negative evidence covers wrapper containment with a persistent exact rejection trace, positive uncontinued CREATE PID and zero Continue calls, absent side-effect marker, and complete cleanup; root/child path, hash, bytes, volume/file-ID, parent/creation, stale or reused PID, unexpected descendant, command-line, and incomplete-cleanup mismatches must be rejected. These focused tests do not constitute Phase 0, a release build, canary, independent gate, or freeze.

#### Frozen invariants

1. V2 synchronous debug events, pre-continuation image identity, exact parent/creation binding, retained handles, independent Job accounting, and fail-closed cleanup remain the sole process-trace contract.
2. No production Host authority, product/protocol/schema semantics, build command, or downstream D32 gate requirement changes.
3. D32 Cargo/build/test Jobs continue to deny Git, SSH, and credential-helper images; this ADR does not authorize those descendants.

#### Supersedes / Superseded by

- Supersedes only the blanket Git-root denial in ADR-D32-PROCESS-EVENT-TRACE-V2 to the exact, standalone caller-pinned root and optional direct pinned conhost described above. All other V2 denials and requirements remain unchanged.
- Supersedes none of the Stage Contract or gate requirements. No D32 gate is declared satisfied.

---

### ADR-D32-RELEASE-OUTPUT-FRESHNESS-QUARANTINE — Exact Release-Output Freshness Exception

**Status:** APPROVED WITH CONDITIONS
**Decision authority:** GPT-6 Sol Max
**Decision date:** 2026-09-27
**Related milestone:** D32 final-gate candidate
**Related baseline:** `e902a05bf3193212c131c78ec7dfe6b72e2c292f`
**Related decisions:** ADR-D32-EVIDENCE-BUNDLE-V1, ADR-D32-PHASE0-TOOLCHAIN-PROFILE, ADR-D32-RELEASE-EVIDENCE-BOOTSTRAP, ADR-D32-GOVERNANCE-V12-RECONCILIATION

#### Context

The fixed Phase 1 release commands must produce fresh artifacts at their contractually fixed target paths, while an already-present stale leaf currently blocks that build. This prospective, D32-only decision defines a recoverable way to clear only the three exact stale leaves without reusing them or weakening the fixed command, clean-candidate, identity, aggregate, or canary requirements.

#### Decision

1. **Exact prospective scope.** A future authorized Phase 1 freshness implementation may quarantine only these leaf files, and only when they already exist at the exact fixed path:
   - `<repo>\vita-agent\target\release\vita-agent.exe`
   - `<repo>\src-tauri\target\release\d32a-production-canary-host.exe`
   - `<repo>\src-tauri\target\release\digital_life_lib.dll`

   No other file, output, directory, target tree, build artifact, candidate, or phase is covered. This ADR authorizes no move in the present repair task.
2. **Recoverable no-overwrite move.** Before any move, require the exact canonical source leaf and all path components to be non-reparse, verify it is a regular file, and establish that no other holder prevents an exclusive opened-handle check. Derive path, bytes, SHA-256, volume serial, and file ID from the same retained opened handle, and preserve that identity fence through the move; a later path re-resolution after releasing it is insufficient. The destination and all of its path components must also be canonical and non-reparse; it must be under a newly created, unique, external quarantine location on the same volume, outside and non-overlapping with the candidate repository. Destination names must be unique and absent. Move only the exact leaf with an atomic no-replace operation bound to that source object. If any precondition or identity is uncertain, do not move and fail closed.
3. **Exact post-move verification.** After the move, prove the original source path is absent and the quarantine leaf is a non-reparse regular file. Reopen it with the required no-holder check and verify its canonical path, bytes, SHA-256, volume serial, and file ID against the pre-move opened-handle snapshot. Any mismatch or inability to prove the move is BLOCKED; retain the quarantined item recoverably and do not delete or overwrite it.
4. **Fresh output is still required.** After the unchanged fixed Phase 1 Cargo commands, each produced release artifact must be established at its unchanged source path using opened-handle identity/hash/bytes evidence. Its volume/file identity must be a newly created identity distinct from the corresponding quarantined stale leaf identity, even if the fresh output has identical bytes and hash. Quarantined content is never build input, reused output, attestation evidence for the new build, or a substitute for the fresh artifact.
5. **All existing gates remain.** Preserve the exact fixed argv, target directories, clean-candidate checks, phase ordering, release attestation/schema, full post-bundle aggregate, required negative evidence, ordered real Host canary, and independent gate. No broad deletion, `cargo clean`, alternate target directory, overwrite, or reuse is allowed.

#### Frozen invariants

1. This is only a release-output freshness-handling exception; production behavior, schema/protocol/trust semantics, toolchain authority, shipping resources, and Stage Contract are unchanged.
2. Phase 0 fixture-output freshness handling remains governed by ADR-D32-PHASE0-TOOLCHAIN-PROFILE and its exact five-file scope.
3. Absence immediately before each fixed Phase 1 command and proof of a fresh file identity after each command remain mandatory.

#### Required evidence

- Future implementation must test each exact source leaf, no-holder and non-reparse refusal, destination collision/no-overwrite refusal, same-volume enforcement, exact pre/post identity/hash/bytes preservation, source absence after move, and new output file identity distinct from the quarantined file.
- Record the exact candidate SHA and clean status around the fixed commands, then run all existing attestation validation and the full required downstream gates against the newly generated artifacts.
- This ADR is authorization of a narrowly defined prospective handling procedure only; it does not itself establish freshness, run Phase 0, pass the aggregate, satisfy a canary, or close D32.

#### Supersedes / Superseded by

- Supersedes only (a) ADR-D32-PHASE0-TOOLCHAIN-PROFILE decision 7's prospective sentence that the three release outputs are “never quarantined,” and (b) ADR-D32-EVIDENCE-BUNDLE-V1's statement that the attestor does not move a prior output, solely to permit this exact pre-build quarantine. The attestor must still fail closed if any exact output remains present immediately before a fixed command; all existing pre-existing-output negative checks, fixed paths, fresh generated artifacts, opened-handle identity, attestation, and other requirements remain mandatory.
- Supersedes no other D32 output policy, gate, or Stage Contract requirement.

---

## ADR 模板

### ADR-XXXX — <标题>

**Status:** APPROVED / SUPERSEDED / BLOCKED  
**Decision authority:** GPT-5.6 Sol / User  
**Decision date:** YYYY-MM-DD  
**Related milestone:** Dxx / Hxx / other  
**Related baseline:** `<exact SHA>`

#### Context

...

#### Decision

...

#### Frozen invariants

1. ...
2. ...

#### Allowed implementation space

- ...

#### Forbidden implementation

- ...

#### Required tests

- ...

#### Required real canary

- ...

#### Required negative evidence

- ...

#### Compatibility constraints

- ...

#### Escalation triggers

- ...

#### Supersedes / Superseded by

...
