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
| ADR-D32-NON-SOURCE-L1-RUNTIME-AND-OUTER-CALLER-V1 | APPROVED WITH CONDITIONS | Full runtime-origin admission and bounded outer-caller evidence for NON_SOURCE_L1 | GPT-6.1 Sol Max | Exact current NON_SOURCE_L1 implementation and separately authorized single batch only |
| ADR-D32-PHASE0-FIXTURE-BUDGET-V1 | APPROVED WITH CONDITIONS | Bounded four-job D32 Phase0 fixture-build budget | GPT-6 Sol Max | Five owner-bound Phase0 fixture builds only |
| ADR-D32-PHASE0-TEST-INVENTORY-AUTHORITY-V1 | APPROVED WITH CONDITIONS | Independently discovered and coordinator-pinned D32 test inventories | GPT-6 Sol Max | Six list-only commands before each formal Phase0 |
| ADR-D32-EVIDENCE-BUNDLE-V1 | APPROVED | D32-A gate evidence bundle 与 clean-source release attestation | GPT-6 Sol | D32-A preflight/evidence only |
| ADR-D32-FIXTURE-TRUST-D31-SEEDER | APPROVED | D32 fixture Git trust 与 D31 recovery seeder evidence | GPT-6 Sol | D32 fixture tooling 与 D31 test-helper evidence only |
| ADR-D32-RELEASE-EVIDENCE-BOOTSTRAP | APPROVED WITH CONDITIONS | D32-A release evidence bundle 两阶段 bootstrap | GPT-6 Sol | D32-A bundle bootstrap ordering only |
| ADR-D32-PHASE0-TOOLCHAIN-PROFILE | APPROVED WITH CONDITIONS | D32 Phase 0 本地矩阵与 caller-pinned build toolchain | GPT-6 Sol | D32 Phase 0 与紧邻 bundle evidence build only |
| ADR-D32-PROCESS-EVENT-TRACE-V1 | SUPERSEDED | D32 Phase 0/release evidence command-processor denial and complete process trace (historical trace-source conditions) | GPT-6 Sol Max | Historical; superseded for implementation by V2 |
| ADR-D32-PROCESS-EVENT-TRACE-V2 | APPROVED | Synchronous Win32 debug events plus independent Job accounting | GPT-6 Sol Max | D32 Phase 0、release evidence build 与相应 provenance only |
| ADR-D32-GOVERNANCE-V12-RECONCILIATION | APPROVED WITH CONDITIONS | D32 candidate governance v1.2 reconciliation and prospective SC-D32-V1 | GPT-6 Sol Max | D32 final-gate candidate only |
| ADR-D32-PINNED-GIT-ROOT-IDENTITY | APPROVED WITH CONDITIONS | D32 fixture tooling caller-pinned direct Git root identity under V2 trace | GPT-6 Sol Max | D32 fixture Git metadata queries only |
| ADR-D32-RELEASE-OUTPUT-FRESHNESS-QUARANTINE | APPROVED WITH CONDITIONS | Exact D32 release-output freshness quarantine exception | GPT-6 Sol Max | Three named Phase 1 release leaves only |
| ADR-D32-PHASE0-COMPACT-EVIDENCE-V1 | APPROVED WITH CONDITIONS | D32 Phase 0 compact external storage and failure-only diagnostic | GPT-6 Sol Max | Prospective D32 Phase 0 schema/storage migration only |
| ADR-D32-POWERSHELL-MODULE-CONTENT-AUTHORITY-V1 | SUPERSEDED (partial) | Caller-pinned closed content authority for installed PowerShell modules | GPT-6.1 Sol Max | Retained except where V2 explicitly supersedes |
| ADR-D32-POWERSHELL-MODULE-CONTENT-AUTHORITY-V2 | APPROVED WITH CONDITIONS | Protected PowerShell distribution and resolver admission | GPT-6.1 Sol Max | D32 PowerShell admission and dependent evidence only |
| ADR-D32-CARGO-PINNED-VCTIP-DESCENDANT-V1 | APPROVED WITH CONDITIONS | Exact Profile V2 VCTIP child under fixed Cargo roots | GPT-6 Sol Max | D32 Phase 0/Phase 1 Cargo process traces only |
| ADR-D32-BOUNDED-COMPILER-DIAGNOSTIC-V1 | APPROVED WITH CONDITIONS | One-shot, bounded, non-gating compiler diagnostic for the exact blocked D32 candidate | GPT-6.1 Sol Max | Prospective diagnostic tooling and separately caller-pinned diagnostic use only; no formal gate authority |
| ADR-D32-BOUNDED-REGISTRY-TAR-FORMAT-V1 | APPROVED WITH CONDITIONS | Strict per-header USTAR/GNU registry archive format and separate caller-pinned diagnostic census | GPT-6.1 Sol Max | Registry archive decoder/proof schemas and a separately authorized diagnostic census only; no formal gate authority |
| ADR-D32-BOUNDED-REGISTRY-TAR-GNU-LONGNAME-V1 | APPROVED WITH CONDITIONS | Strict bounded GNU L long-name control records and fully cross-bound diagnostic census/proof schema migration | GPT-6.1 Sol Max | GNU L registry decoding/proof schemas and a separately authorized new-candidate census only; no source-proof or formal gate authority |

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

### ADR-D32-PHASE0-COMPACT-EVIDENCE-V1 — Phase 0 紧凑外部存储与失败诊断

**Status:** APPROVED WITH CONDITIONS
**Decision authority:** GPT-6 Sol Max
**Decision date:** 2026-09-27
**Related milestone:** D32-A final-gate readiness
**Related baseline:** `92ce5f7ac48e87c4ddeee3f92f1e6851c4172c49`
**Related decisions:** ADR-D32-PHASE0-TOOLCHAIN-PROFILE; ADR-D32-PROCESS-EVENT-TRACE-V2; ADR-D32-EVIDENCE-BUNDLE-V1; ADR-D32-RELEASE-EVIDENCE-BOOTSTRAP

#### Context

The current Phase 0 output basename combined with the pinned source/output paths can exceed the practical Windows path budget. A prospective compact layout can shorten only the fresh external evidence storage paths while retaining the fixed source, command, toolchain, trace, and gate contracts. Failed runs also need durable failure evidence that cannot be confused with a Phase 0 PASS.

#### Decision

1. **Fresh owner-bound root.** A Phase 0 run uses one caller-selected canonical absolute `EvidenceRoot` outside and non-overlapping with the candidate repository. Its parent must already exist and be non-reparse; the exact root must be absent and created exclusively. Reparse-backed roots, collisions, stale IDs, or changed opened-handle identities fail closed. After exclusive root creation, a create-new identity-bound owner marker binds the exact candidate SHA, caller-pinned profile path/SHA/bytes/opened-file identity, opened EvidenceRoot path/identity, and full lowercase 32-hex `run_id`. The run ID is also retained in code-owned records. Validate the root and every compact child directory by opened-handle identity.
2. **Fixed compact Cargo storage.** The per-run root is exactly `EvidenceRoot\r`; fresh `CARGO_HOME` and `TEMP` are exactly `EvidenceRoot\r\c` and `EvidenceRoot\r\t`. `CARGO_HOME` must be empty before the exact locked fetches. Do not use a junction, `subst`, system LongPaths policy change, alternate source path, reused cache, or a changed fixed Cargo argv, toolchain profile, or process trace.
3. **Prospective strict schema migration.** The new candidate uses fixture-build provenance V3, Phase0 matrix V3, release-build attestation V4, and post-bundle aggregate V3. Each reader/consumer accepts only its exact current version and rejects previous and unknown versions. Toolchain profile V2, debug/Job process trace V2, fixture manifest v3, and the separate D31 recovery-seeder provenance V2 remain unchanged. This decision does not relabel, upgrade, or rebind evidence from the prior candidate; old-SHA quarantine evidence and leaves remain preserved and locked.
4. **Failure-only diagnostic sidecar.** After owner binding, an early Phase 0 failure may create `D32-PHASE0-BLOCKED-DIAGNOSTIC.json` as `D32_PHASE0_BLOCKED_DIAGNOSTIC_V1`, using create-new semantics only. It records the candidate/profile/root/run binding, failing fixed command and process identity when available, raw V2 trace, raw Job/debug cleanup including explicitly unverified fields, ordered raw stdout/stderr references with hash/bytes/opened-file identities when captured, and primary plus secondary errors. Unavailable command/process/capture/cleanup evidence must remain explicitly unverified. The sidecar grants no PASS or Gate authority; Phase 1 and aggregate consumers reject any such sidecar regardless of its contents. If diagnostic persistence fails, preserve the original primary error and append the diagnostic-capture error; never infer cleanup or PASS from missing diagnostic evidence.
5. **Existing stage contract is unchanged.** Keep all five fixture phases, full required protocol/Vita/Host suites, named checks, fixed inventory and negative evidence. This decision authorizes no Phase 0/Cargo/network execution, release build, real move, canary, independent gate, or stage closure by itself.

#### Frozen invariants

1. Compact storage changes only prospective external evidence paths and record versions. Candidate source paths, exact commands, profile/toolchain authority, fixture manifest shape, trace semantics, cleanup semantics, provider/tool contract, and downstream gate requirements remain unchanged.
2. A blocked diagnostic is failure evidence only and can never authorize Phase 1, aggregate PASS, or any downstream gate.

#### Required tests and evidence

- Verify the fixed compact layout against the longest known 286-character Codex `.snap` full path (replace its old 74-character Cargo-home prefix with the 11-character compact `E:\p0r3\r\c` prefix) and, when safe, a full pinned-tree path census. The resulting reference path is 223 characters; the read-only pinned-tree census reported a maximum projected compact path of 230 characters against the measured 247-character directory-path limit. This does not replace exclusive-root, non-reparse, or opened-handle identity checks at run time. If the approved paths cannot meet the applicable path budget without a prohibited policy/path workaround, stop as an architecture blocker.
- Test exclusive fresh-root creation, owner-marker binding, reparse/collision/stale-run-ID refusal, and opened-handle identity changes for root and compact child directories.
- Test strict old/unknown schema rejection at each producer/reader/consumer, forged log/sidecar refusal, early-failure diagnostic persistence and cleanup representation, and release/aggregate refusal when a blocked diagnostic exists.
- Preserve the existing exact five fixture phases, required full suites and named checks, and all required negative/canary obligations; no PASS is established by focused self-tests.

#### Supersedes / Superseded by

- Supersedes only the prospective Phase 0 storage basenames and the affected schema-version numbers in earlier D32 tooling decisions. It does not supersede or alter the profile, trace, fixture-manifest, D31 seeder, fixed argv, real-canary, negative-evidence, independent-gate, or final-freeze requirements.

---

### ADR-D32-CARGO-PINNED-VCTIP-DESCENDANT-V1 — Exact VCTIP Child Under Fixed Cargo Roots

**Status:** APPROVED WITH CONDITIONS
**Decision authority:** GPT-6 Sol Max
**Decision date:** 2026-09-28
**Related milestone:** D32-A final-gate readiness
**Related baseline:** `7ecab45f343eb48636b61a046f224d61368e01a1`
**Related decisions:** ADR-D32-PHASE0-TOOLCHAIN-PROFILE; ADR-D32-PROCESS-EVENT-TRACE-V2; ADR-D32-PINNED-GIT-ROOT-IDENTITY; ADR-D32-PHASE0-COMPACT-EVIDENCE-V1

#### Context

The approved caller-pinned MSVC toolchain launches `vctip.exe` as a Cargo build descendant. A blanket basename denial blocks the fixed D32 Cargo commands, while a basename or broad-path exemption would grant unbounded helper authority. This decision permits only the single exact toolchain image under the already pinned Cargo process tree.

#### Decision

1. For D32 Phase 0 and Phase 1 only, a `vctip.exe` descendant may be continued only when the current caller-pinned Profile V2 contains exactly one matching image record at `E:\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\vctip.exe` with 335328 bytes, SHA-256 `e175c981ca866689bf8f8d9bd5ba1e71e2eb1c9d389de555744b0cb439250996`, volume serial `749614a1961465c0`, and file ID `0b5d2000000001000000000000000000`.
2. Immediately before `ContinueDebugEvent`, require the observed image's opened `hFile` identity to match that exact record; the root to be the fixed Cargo image selected from the same validated profile; the process to have an active retained parent identity in the accepted CREATE chain; and the process to be in the exact owned Job whose verified extended flags are only `KILL_ON_JOB_CLOSE` (breakaway and silent breakaway disabled). Any missing, stale, conflicting, or unverifiable check blocks that CREATE with zero Continue calls and no child user-code marker.
3. The narrow exception is not a basename allowlist. An unpinned, renamed, copied, drifted, duplicate, wrong-profile, or otherwise mismatched VCTIP image is blocked. VCTIP content at another path/name is not admitted as an ordinary pinned toolchain or candidate-target image. All other command-processor, shell, Git, SSH, credential-helper, script, and helper denials remain unchanged.
4. Preserve Profile V2, process/Job trace V2, unique CREATE/EXIT identity accounting, independent Job accounting, full cleanup verification, fixed command arguments, and production Host authority. This decision adds no user-code authority and changes no Stage Contract, invariant, schema, or downstream gate.

#### Required tests and evidence

- Exercise the exact profile record and exact opened-handle identity as the only positive VCTIP admission; reject each changed path, byte count, SHA, volume serial, file ID, Cargo root, profile, duplicate/copy, and parent-chain case.
- Verify a renamed/unpinned VCTIP CREATE is left uncontinued with zero CREATE Continue calls, no child marker, and complete V2 debugger/Job cleanup.
- Verify the owned Job flags remain exact kill-on-close with both breakaway flags absent; preserve all existing command and helper denial tests.
- A focused positive policy/self-test is not a formal Phase 0/Phase 1 result and does not authorize release, canary, aggregate PASS, Gate, or stage closure.

#### Supersedes / Superseded by

- Supersedes only the blanket name-only denial of the exact caller-pinned VCTIP descendant described above. No other launch denial, process-trace requirement, cleanup requirement, toolchain trust rule, or gate is superseded.

---

## ADR-D32-LOCKED-VENDORED-PROTOC-V1 — Exact locked protoc image authority for D32 builds

**Status:** APPROVED WITH CONDITIONS
**Decision authority:** GPT-6 Sol Max
**Decision date:** 2026-09-28
**Related milestone:** D32-A-R2 / Phase0 and Phase1
**Related baseline:** `db77636fbb8e6afcfb25a8dd026b0f75e4879ddd`

### Context

The first locked Vita fetch can introduce a vendored `protoc.exe` from a crates.io package into the run's fresh Cargo registry source tree. The existing process policy intentionally rejects that executable by name. The exception must prove exact immutable source, exact extracted bytes and opened identity before any child is continued, while preserving fixed Cargo commands and the existing V2 Job/debug authority.

### Decision

1. A Coordinator-created external `D32_VENDORED_PROTOC_AUTHORITY_V1` record is create-new and independently pinned by SHA-256 before a Phase0 run. It binds the exact candidate SHA, Profile V2 path/hash/opened identity, fresh EvidenceRoot and fixed `r\c`/`r\t` layout, Vita lock identity, package tuples, and immutable archive/image pins. The authority is valid only for D32 Phase0/Phase1; its hash must never be inferred from the record being validated.
2. The only accepted package tuples are `protoc-bin-vendored` and `protoc-bin-vendored-win32`, both version `3.2.0`, source `registry+https://github.com/rust-lang/crates.io-index`; their lock checksums are respectively `d1c381df33c98266b5f08186583660090a4ffa0889e76c7e9a5e175f645a67fa` and `95067976aca6421a523e491fce939a3e65249bac4b977adee0ee9771568e8aa3`. The win32 archive must be the canonical Cargo cache entry under the exact owner-bound fresh CargoHome, hash/length bound to the locked checksum, and contain one unique regular `bin/protoc.exe` member of 11,934,496 bytes with SHA-256 `cbd1ca1fd6afd1bb6ddd1c09c118ecd4c50f928980857f16fe6fc23704ea17e2`.
3. After the three fixed online fetches, in-process code may validate the exact archive and create-new materialize its package tree only at Cargo's canonical registry source slot. Traversal, aliases, duplicate/case-colliding entries, reparse points, unexpected files, stale or foreign home, and existing mismatched content are blocked. No tar executable, helper process, extra Cargo argument, copied executable, alternate source, or reused cache is authorized.
4. A create-new `D32_PHASE0_VENDORED_PROTOC_RUN_GRANT_V1` binds the authority reference, current candidate/profile, owner marker, fresh run ID/root/CargoHome, lock/archive/source tree, and extracted executable opened identities. Each debug CREATE is continued only when the exact granted path, bytes, hash, volume serial, file ID, accepted parent chain, and existing non-breakaway Job conditions pass. Unknown helpers remain denied; rejected CREATE retains `Continue=0`, no user marker, and full V2 debugger/Job cleanup proof.
5. Set `PROTOC` only for the fixed D32 `src-tauri` fixture/test/release Cargo commands, using the exact granted path. Vita code-mode resolves its vendored path without `PROTOC`; ambient `PROTOC`, shell, command processor, Git, SSH, credential helper, script, or other helper authority remains prohibited. Fixed Cargo argv, target, features, toolchain pins, Profile V2, Trace V2, production Host authority, SC-D32-V1 and frozen §16.1.5 do not change.
6. Migrate fixture-build provenance V3→V4, Phase0 matrix V3→V4, release attestation V4→V5, and aggregate V3→V4. All readers reject prior and unknown versions. Fixture manifest v3, D31 seeder provenance V2, Profile V2, and debug/Job trace V2 remain unchanged. The Phase0 failure payload latch must preserve the terminal failing phase's trace and cleanup in the one existing blocked-diagnostic V1 record; it does not gain PASS or Gate authority.
7. The post-aggregate D31 recovery seeder may use the same immutable locked source/image pin only under a distinct fresh seeder run/home, create-new owner marker, and separate per-run grant. Phase0/Phase1 authority cannot be replayed. A separate D32-only versioned companion helper-auth/trace attestation must bind the unchanged D31 seeder provenance V2 record and artifact by hash/identity and be validated by Coordinator/Luna High. This is a separate required implementation batch and is not included in the Phase0/Phase1 authority record or the current Phase0 implementation scope.

### Frozen invariants and forbidden implementation

- Do not change SC-D32-V1, Stage Contract, fixed command arguments, Cargo jobs, target directories, feature set, toolchain/profile schema, V2 trace schema, Job policy, Host production authority, §16.1.5, or the V1 blocked-diagnostic schema.
- Do not admit protoc by basename, signature, wildcard path, package name alone, ambient resolution, detached copied bytes, stale CargoHome, old run, mismatched profile, unexpected parent, or changed file identity.
- Do not run formal Phase0/Phase1, release, canary, aggregate PASS, Gate, or D33 as part of the implementation batch.

### Required tests and negative evidence

- Verify exact lock/package/archive/member pins and canonical Cargo slots; reject wrong package/version/source/checksum, archive alias/traversal/special or duplicate member, copied/renamed/changed image, wrong run/root/profile/home, stale grant, changed file ID, unexpected parent, breakaway Job, ambient PROTOC, and any unknown helper.
- Verify a denied protoc CREATE stays uncontinued with zero Continue calls and no user marker, with complete V2 event accounting and Job/debug cleanup.
- Verify V4/V4/V5/V4 consumers reject prior and unknown versions; Phase1 and aggregate refuse blocked diagnostics; a later fatal phase's raw V2 trace and cleanup are not hidden by an earlier failure.
- Keep D31 seeder V2 Host consumption unchanged until its separate companion attestation and grant are implemented; never replay Phase0/Phase1 authority.

### Supersedes / Superseded by

- Supersedes only the blanket denial of the exact, locked, per-run-authorized vendored protoc image within D32 Phase0/Phase1. The separate D31 seeder allowance requires its own grant and companion evidence. All other launch denials and gates remain in force.

---

## ADR-D32-PHASE0-TAURI-SOURCE-AND-H7C-GIT-V1 — Exact tauri-macros patch and H7-C suite Git child

**Status:** APPROVED WITH CONDITIONS
**Decision authority:** GPT-6 Sol Max
**Decision date:** 2026-09-29
**Related milestone:** D32-A-R2 / Phase0 and Phase1
**Related baseline:** `ddfd21a051d2fcefa0fc6cab2112f29a87440d81`

### Context

The full fixed Vita Phase0 suite includes H7-C tests that create deterministic Git workspaces and invoke the pinned Git image. The exact-source tauri-macros 2.6.3 patch also needs a code-owned, verifiable link from the immutable registry archive to its sole candidate-local change. Neither exception may turn the existing child-process policy into basename, wildcard, or general helper authority.

### Decision

1. The only approved tauri-macros patch source is the exact locked crates.io `tauri-macros` 2.6.3 archive (34,903 bytes, SHA-256 `e8b394794f399a421811d06966343e7933fcae92d59f5180b9388d1174497a45`) whose 15 regular members match the pinned source tree. The only local change is `src/command/wrapper.rs`, with patched source SHA-256 `1bac6f2bdb822c890f7c645560dcb3c28737908c5aebaafd2c2e0742cb05593b`, vendor tree SHA-256 `52842cfa519dd31f59d684bcbd7fedc19bb709081ca16c9b9d0741b08594fb1b`, and patch descriptor SHA-256 `a8d76c969d38c9525762906955a51b33fec360a174dc2ff3a6051be3db4021cd`. Root and vendored Cargo metadata are separately pinned by the source attestation implementation. A stdout-only source-facts generator does not itself authorize use: before a run, the external `D32_TAURI_MACROS_SOURCE_PATCH_V1` record must be create-new, independently SHA-pinned, and bind exact candidate, Profile V2 path/SHA/bytes, archive bytes/SHA, source tree, sole diff, vendored tree and all relevant Cargo metadata. Each producer/reader reopens and checks its exact external reference and current candidate-local files.
2. The only additional child launch admitted by this decision is the exact caller-pinned direct Git.exe image as a child of the accepted Vita libtest, itself a direct child of the fixed Cargo root, during the one fixed `vita-full-local-suite` Phase0 command and in that command's existing nonbreakaway Job. No Git executable by name, alternate path, shell, `cmd.exe`, SSH, credential manager/helper, arbitrary descendant, or per-test process attribution is admitted.
3. Before the one-shot Phase0 run, the Coordinator creates and independently pins a `D32_PHASE0_H7C_GIT_CHILD_AUTHORITY_V1` record binding candidate/Profile, exact intended EvidenceRoot and TempRoot paths, exact Git opened-file identity, fixed full-suite argv/working directory/timeout, and finite command/environment/parent/Job policy. After the runner binds the fresh root, owner marker, run ID and `r\t` TempRoot, it creates a no-overwrite `D32_PHASE0_H7C_GIT_RUN_GRANT_V1` binding those actual opened identities and 35 exact fresh slots `d32-h7c-slot-01..35`, each with `repo` and `git-home\empty.gitconfig`. Each slot permits only the ordered five setup argv records (`init`, fixed name/email config, `add`, `commit`) and at most one exact fixed read-only status argv. The setup/status environment maps are explicit and deny PATH, shell/helper configuration, ambient config overrides, and other environment keys.
4. Every admitted Git CREATE is validated before Continue against retained opened image bytes/SHA/volume/file ID, complete argv, current directory handle and authorized slot/config identities, sanitized environment, parent PID+creation chain, and same Job. An unapproved CREATE is left uncontinued with zero CREATE Continue calls, no user marker, and complete V2 debug/Job accounting and cleanup. The companion `D32_H7C_GIT_CHILD_ATTESTATION_V1` binds the Phase0 suite's exact stdout/stderr, V2 process trace and all observed Git process identities, and requires every code-owned 43 `h7c_*` plus three real H7-C test result rows exactly once with `ok`; process-to-test attribution remains `NONE`.
5. Phase0/Phase1 protoc authority is not silently broadened by this record. The post-aggregate D31 recovery seeder may use the same immutable protoc source/image only with its separately approved fresh seeder run/home, owner marker, independent per-run grant and D32-only companion attestation; it never replays a Phase0/Phase1 grant. D31 seeder provenance V2 and its strict Host consumer remain unchanged.
6. Migrate fixture-build provenance V4→V5, Phase0 matrix V4→V5, release attestation V5→V6, and aggregate V4→V5. Every current reader rejects prior and unknown versions. Profile V2, debug/Job trace V2, fixture manifest v3, D31 recovery-seeder provenance V2, SC-D32-V1, frozen §16.1.5, fixed Cargo argv/targets/features, the full required Phase0 suites, and required negative evidence remain unchanged.

### Frozen invariants and forbidden implementation

- Do not relax exact candidate/Profile/root/run/owner/home/slot/image identity, the V2 trace/Job requirements, or the pre-Continue boundary.
- Do not allow package name, Git/protoc basename, signature, wildcard path, copied/renamed image, ambient resolution, arbitrary helper, stale grant, or parent-chain shortcut to create authority.
- Do not reduce the five fixture phases, full protocol/Vita/Host suites, H7-C real tests, negative tests, or any later Stage Contract requirement.
- Do not change SC-D32-V1, §16.1.5, fixed Cargo argv/toolchain, Host production authority, Profile V2, Trace V2, fixture manifest v3, or D31 seeder V2.

### Required tests and negative evidence

- Verify archive/member/tree/sole-diff/Cargo metadata binding; reject malformed archive, mismatched vendor tree, wrong candidate/profile/hash/identity, copied or changed bytes, and unknown source authority versions.
- Verify H7 authority/grant rejects stale or wrong run, candidate, profile, root, TempRoot, owner marker, Git identity, slot identity, argv, environment, parent, or Job; verify rejected CREATE remains uncontinued with no marker and complete V2 cleanup.
- Verify companion attestation rejects forged/missing/duplicate/failing result rows, altered stdout/stderr or trace, substituted authority/grant, and unmatched Git identities; confirm 46 fixed H7-C result rows are all present.
- Verify V5/V5/V6/V5 current readers reject prior and unknown versions; Phase1 and aggregate refuse any blocked-diagnostic sidecar.

### Supersedes / Superseded by

- Supersedes only the prior blanket denial of the exact-source tauri-macros local patch and exact granted Git.exe child described above. All other process denials, fixed suites and gates remain unchanged. Any future expansion requires a separate explicit architecture decision.

---

## ADR-D32-PHASE0-FIXTURE-BUDGET-V1 — Bounded four-job Phase0 fixture builds

**Status:** APPROVED WITH CONDITIONS
**Decision authority:** GPT-6 Sol Max
**Decision date:** 2026-09-29
**Effective:** prospective only
**Related milestone:** D32-A-R2 / Phase0 and Phase1
**Related baseline:** `06c300d94792e2a9aed4c47cb1db7b1a69551861`

### Context

Repeated cold Phase0 attempts showed that the first fixture build can exceed several hours. The existing Phase0 contract has a fixed one-job build path and a bounded command deadline. This decision permits a narrowly scoped, resource-gated concurrency and timeout change for the five local fixture builds only; it does not change which evidence those builds establish or authorize a broader Cargo invocation.

### Decision

1. Keep all three ordered locked fetch commands and their command timeout at exactly 14,400 seconds. Keep the Phase0 command timeout at 14,400 seconds for tool probes, test listing, the H7 authority suite, all local suites, focused checks, and every other non-fixture command. The default Phase0 timeout remains 1,800 seconds for non-formal callers; formal Phase0 must explicitly supply `-Phase0TimeoutSeconds 14400`.
2. For the exact five ordered owner-bound Phase0 fixture builds only—H1 authority Host, H7 authority Host, H7 process, H7 Git helper, and D32-A sandbox—permit only the otherwise fixed `cargo build` argv with `--jobs 4` and an explicit per-build `-Phase0FixtureBuildTimeoutSeconds 28800`. No other argv token, package, manifest, feature, target, target directory, toolchain, or ordering changes. Formal Phase0 must explicitly pin that parameter to 28,800. Standalone/default fixture invocations remain 600 seconds and jobs=1 and cannot attest a Phase0 fixture budget. Phase1 release commands and the D31 recovery seeder remain unchanged.
3. The Phase0 runner must measure and record, before creating the fresh owner-bound build environment, at least eight logical processors, at least 12 GiB available physical memory, at least 200 GiB free on the evidence volume, and zero competing cargo/rustc/cl/link/build-script writers for the candidate's target trees. Because the Windows process census does not provide a reliable working directory, fail closed if any process in those build classes is active; do not infer that it is unrelated from a command line lacking a candidate path. Failure or inability to measure any threshold is BLOCKED before Cargo. Record the exact observed capacity in strict `D32_PHASE0_FIXTURE_BUILD_BUDGET_V1` fields in fixture provenance V6 and Phase0 matrix V6; consumers require exact jobs/timeouts and enforce the recorded capacity minima.
4. Retain a new, empty, owner-bound `r\c` CargoHome and `r\t` TempRoot, the current locked fetches, normal repository target directories, and the existing V2 debug/Job policy and pre-Continue image checks. Four concurrent Rust compiler processes may be active within the same verified nonbreakaway Job. Do not copy an old Cargo cache, set a target-dir override, change native process/accounting rules, clear caches, or enlarge the five-output quarantine scope.
5. Strictly migrate fixture provenance V5→V6, Phase0 matrix V5→V6, release attestation V6→V7, and aggregate V5→V6. Every producer, reader, validator, and test rejects the prior and unknown versions and rejects wrong argv/budget. Preserve fixture manifest v3 and its six original `environment` fields, Profile V2, debug/Job Trace V2, protoc/source/H7 authorities V1, D31 recovery-seeder provenance V2, and bundle manifest v1. A BLOCKED run has no PASS or gate authority.

### Frozen invariants and forbidden implementation

- The full five-build Phase0 fixture inventory, three fetches, complete local suites, focused checks, H7-C negative evidence, and all existing downstream gates remain mandatory.
- The only Cargo concurrency change is `--jobs 4` on those five fixture build commands; the only longer deadline is their explicit, individually bounded 28,800-second timeout. The 14,400-second Phase0 non-build command ceiling remains exact.
- Fresh CargoHome, no cache copy, no target override, fixed toolchain/environment, V2 process-event verification, Job accounting, identity checks, and cleanup conditions remain unchanged.
- Do not apply this budget to test commands, Phase1 release builds, D31 seeder builds, standalone fixture runs, other candidates, or any other stage.

### Required tests and negative evidence

- Accept only the exact five jobs=4 fixture argv records and 28,800-second build limit; reject jobs 1, 2, or 5 and timeout 14,400 or 28,801. Reject changed fetch/test/release argv, a missing or extra fixture, wrong order, budget drift, and old/unknown schema versions.
- Reject insufficient or unverifiable CPU/RAM/evidence-volume capacity, any competing target writer, wrong candidate/profile/root/owner/home, stale artifacts/grants, or non-fresh CargoHome.
- Preserve V2 trace identity/accounting under concurrent process events; reject partial, duplicate, out-of-order CREATE/EXIT sequences, missing EXIT, unknown child images, denied cmd/Git CREATE with zero Continue and no marker, breakaway Job, and residual Job members. Require full existing debugger/Job cleanup evidence.

### Supersedes / Superseded by

- Supersedes only the prospective jobs=1 / 600-second fixture-build budget for the exact five owner-bound Phase0 fixtures. It does not supersede the fixed five-phase scope, test parallelism, any fixed fetch/test/release command, toolchain, trace, authority, security rule, or gate. Any further budget or concurrency change requires a separate architecture decision.

---

## ADR-D32-PHASE0-TEST-INVENTORY-AUTHORITY-V1 — Independent test-inventory discovery and pin

**Status:** APPROVED WITH CONDITIONS
**Decision authority:** GPT-6 Sol Max
**Decision date:** 2026-09-29, prospective
**Related milestone:** D32 final-gate readiness (D32-A-R2)
**Related baseline:** `756acd388620f7511034e7f3e8886fefb9ff6ea3`

### Context

Repeated source/manifest changes make a code-authored fixed `cargo test -- --list` name table an unsafe authority for the current exact candidate. Conversely, a formal Phase0 runner must not accept its own first observation as the test baseline. Inventory must be observed in a separate, monitored, candidate/Profile/lock-bound preparation run, reviewed independently, and pinned by the Coordinator before the expensive formal Phase0 attempt.

### Decision

1. Before any formal Phase0 root is claimed, run a separate list-only inventory discovery against the exact clean candidate. The discovery uses a new exclusive external canonical non-reparse EvidenceRoot with a create-new owner marker, compact `r\c` CargoHome and `r\t` TempRoot, both fresh and owner-bound. It binds the caller-pinned Profile V2, exact candidate SHA, all three Cargo.lock inputs, source-patch authority, and a separate discovery-only protoc authority/grant for that fresh CargoHome. The discovery performs exactly the three existing fixed locked fetch commands at 14,400 seconds, then exactly six ordered Cargo list commands: protocol all/ignored, Vita all/ignored, Host all/ignored. Each list command adds only `--jobs 4` before the `--` test-harness separator and has the explicit 28,800-second `Phase0InventoryListTimeoutSeconds` deadline. No test bodies execute in discovery. It uses the existing V2 process Job/debug/CREATE/EXIT/retained-handle/accounting/cleanup policy. H7-C Git authority is not used.

2. Discovery writes create-new `D32_TEST_INVENTORY_DISCOVERY_V1`, with `gate_authority = NONE`, exact clean SHA before/after, owner/root/CargoHome/TempRoot opened identities, current profile/lock/source/protoc references, all fetch/list argv/process identities and ordered stdout/stderr references, and complete parsed list rows, summaries and digests. The parser accepts only complete libtest list grammar with one reconciled summary, unique well-formed full names/kinds, no unknown/truncated/duplicate rows, nonempty `all` inventory, and the `ignored` list as a unique subset of `all`; a valid empty ignored list is permitted.

3. A separate create-new `D32_TEST_INVENTORY_BASELINE_V1` is produced in an external path from the validated discovery. It is explicitly `AWAITING_COORDINATOR_PIN` and `gate_authority = NONE`; producing or validating it never authorizes itself. It binds candidate, Profile V2 path/hash/bytes/opened identity, target, three locks, source/protoc references, discovery file/root/run/CargoHome/TempRoot identities, all six exact list commands, their raw captures/process traces, and the sorted UTF-8 package/kind/full-name/category rows. It carries per-package and combined counts/digests and classifies entries as ordinary, ignored, deferred, or focused. The Coordinator independently reviews the exact candidate's source/manifest/config and discovery evidence, then separately pins the baseline's path and SHA-256 for the one formal run.

4. Formal Phase0 requires the externally supplied baseline path and independently pinned SHA-256 before it creates or claims its own EvidenceRoot. It reopens and validates the pinned baseline and its linked discovery through stable opened-file snapshots, then performs the same six ordered list commands in the formal root with exact jobs/timeout/tool/feature/target/lock policy. All six formal output sets, categories, counts and digests must exactly equal the pinned baseline before full suites start. Full-suite per-test results and focused-test results must reconcile by exact full name and expected category/status against that baseline; counts alone are insufficient. Missing, added, removed, renamed, duplicate, malformed, ignored-subset, summary, digest, command, feature, target, toolchain, candidate, root, owner, grant or profile mismatches are BLOCKED.

5. Release attestation, aggregate, and independent-gate readers must independently validate and bind the baseline and discovery references to the same exact Phase0 record/candidate/profile, including their external file hashes and opened identities; stale, missing, tampered, self-generated-but-unpinned, or cross-run references are rejected. New strict schemas are discovery V1 and baseline V1, Phase0 V7, release attestation V8, and aggregate V7. Fixture provenance V6, fixture manifest v3 and its six fields, Profile V2, Trace V2, source/protoc/H7 authority V1, bundle manifest v1, and D31 seeder provenance V2 remain unchanged. Every migrated reader rejects prior and unknown versions. No fixed fixture, suite, focused check, negative evidence, release command or downstream gate is removed or weakened.

### Frozen constraints and stop conditions

- Keep the three locked fetch argv, five fixture builds and their approved jobs=4/28,800 budget, all Phase0 suites/focused checks and their existing timeouts, default test parallelism, toolchain, normal target paths, fresh owner-bound CargoHome, V2 trace/Job policy, child-image authority and cleanup unchanged.
- The six inventory listing commands alone use jobs=4 and 28,800 seconds; do not add a global jobs environment variable or change suite/focused/release/D31 command arguments.
- Discovery is separate from the formal attempt and cannot create or infer the Coordinator baseline pin. It grants no H7 Git exception, PASS, Phase1, aggregate, release, canary or gate authority.
- This decision authorizes implementation and no-Cargo validation only. No inventory discovery/Cargo/fetch/formal Phase0/root/authority creation is authorized by this ADR alone.

### Supersedes

For newly produced Phase0 evidence only, supersedes the earlier requirement that `--list` output equal an immutable code-authored inventory table. The requirement for an exact, complete, independently validated inventory is preserved and is now supplied by the Coordinator-pinned discovery/baseline pair. All other Stage Contract, security, authority, fixture, test, and gate requirements remain in force.

---

### ADR-D32-POWERSHELL-MODULE-CONTENT-AUTHORITY-V1 — Caller-pinned installed-module content and startup admission

**Status:** APPROVED WITH CONDITIONS
**Decision authority:** GPT-6.1 Sol Max
**Decision date:** 2026-09-30
**Effective:** prospective only; no prior evidence is rebound
**Related milestone:** D32 final-gate readiness (D32-A-R2)
**Related baseline:** `28c579267a71ba80f06d5ba77081f7b0cf987867`

#### Context

The accepted direct PowerShell runner can resolve cmdlets through module autoload before its existing caller-pin checks. `-NoProfile` prevents profile startup code but does not make installed PSHOME modules trusted content. Path/name/version/signature checks do not bind the complete code and data closure that can affect module import or command resolution. PowerShell admission therefore needs an explicit external content authority before any installed module is imported.

#### Decision

1. The existing source/build trust premise does not implicitly authorize every module under installed PSHOME. The trust base remains the OS, CLR, PowerShell Core and a candidate-owned module-free bootstrap. This is not a hermetic-runtime claim.
2. A Coordinator independently pins a create-new external `D32_POWERSHELL_MODULE_CONTENT_AUTHORITY_V1` schema-1 document by exact path and SHA-256. It binds the exact candidate SHA, canonical repository, caller-pinned Profile V2 path/SHA/bytes/opened identity, exact PowerShell host identity, PSHOME identity and three fixed roles in import order: `Microsoft.PowerShell.Management`, `Microsoft.PowerShell.Utility`, `CimCmdlets`. For each role it binds the exact manifest, implementation/nested module, RequiredModules, ScriptsToProcess, RequiredAssemblies and every other non-bootstrap file affecting import-time parsing or resolution. Every file binds canonical path, bytes, SHA-256, volume serial and 128-bit file ID; each role and the complete ordered inventory have deterministic digests. Manifest-to-PSHOME-root DLL relationships are fixed and explicit. Module name, version, signature, prefix, wildcard or path alone is never content authority.
3. The external authority is data only and grants no PASS or gate authority. Its candidate output generator is module-free and create-new; it cannot self-authorize. An independently supplied caller pin is mandatory before module import.
4. A controlled fresh direct runner first disables module autoload, then uses only module-free .NET/Core operations to validate the true current `-File` operand and finite accepted host switches, exact Profile/auth/Git/candidate/repository pins and all cross-bindings. It opens and holds stable handles for the complete module closure and every ancestor, checks exact object identity and content, and prevents writes, replacements, redirects or namespace changes through the complete import window. If the runtime/filesystem cannot establish that fence, it fails closed. Only then may it import the three fixed manifests in order and verify actual loaded module, assembly and command origins. Hash-then-release-then-path-import is insufficient proof. Phase boundaries and library reuse revalidate the retained fence and all pins; mutable globals, module names or paths cannot create admission.
5. The accepted startup is an exact pinned `pwsh.exe` direct invocation using `-NoProfile -File <current exact runner>` with only a finite documented set of unambiguous host switches. The validator binds the actual `-File` operand. `-ConfigurationFile`, `-Command`, `-EncodedCommand`, `-CommandWithArgs`, wrappers, sessions and unknown/ambiguous host switches are rejected. Any externally controlled launcher must prove the same conditions. A script that rejects configuration after startup may not claim it ran before startup or that pre-import marker count was zero.
6. The no-pin real-module SelfTest exception is cancelled. Real SelfTest and LoaderSelfTest must complete Profile V2/content-admission before any module import; mode-required Git/Profile pins are rejected before import if missing. No-pin operation is limited to module-free bootstrap, schema and negative checks and records `import_attempts=0`; it cannot import modules, create a child, run Cargo/network, claim a formal root, or claim a gate. Facts generators may emit untrusted candidates using only module-free code to avoid circular authority.
7. Every producer embeds a strict shared `D32_POWERSHELL_MODULE_ADMISSION_V1` record in its normal evidence. It binds the independently pinned authority/Profile/Git references, actual runner process identity, accepted startup and entry-script content identity, module closure/import order/admission, and actual module/assembly/command-origin verification. No per-run companion is introduced.
8. Strict migrations are fixture provenance V6→V7, inventory discovery V1→V2, inventory baseline V1→V2, Phase0 matrix V7→V8, release attestation V8→V9, and post-bundle aggregate V7→V8. Every current producer, reader, validator, inline fixture, nested reference and gate reader rejects prior/unknown versions. Baseline binds both discovery's producer admission and its own baseline-producer admission; it cannot copy the discovery record and claim it as its own. Other D32 module entry points and dot-sourced libraries require the same admission or validated context reuse. Profile V2, Trace V2, fixture manifest v3 with its six environment fields, bundle manifest v1, source/protoc/H7 authorities V1, owner marker, blocked diagnostic V1 failure-only semantics, D31 seeder provenance V2 and Host consumption remain unchanged. Any later D31 companion must bind seeder process admission; it cannot change Host consumption.
9. The SC-D32-V1 sequence, argv, jobs, deadlines, five fixture phases, full suites/focused checks, V2 Job cleanup, fresh roots and quarantine scope are unchanged. This decision grants no discovery, formal run, root-claim, release, canary or gate permission and establishes no D33 work.

#### Frozen constraints and forbidden implementation

- Do not trust ambient module/assembly resolution or broaden the fixed module roles. Do not claim a hermetic OS/runtime boundary.
- Do not install files, change ACLs/OS policy, mutate installed PowerShell modules, use arbitrary helper DLLs, introduce a copy/mirror tool, read real Codex/provider configuration, or change production/frozen authority.
- Do not weaken Profile V2, Trace V2, fixture manifest v3, fixed argv/jobs/deadlines, D31 seeder V2 or any SC-D32-V1 gate.
- Do not reuse earlier no-pin module-import SelfTest, 28c5792 authority inputs or evidence for a later candidate SHA.

#### Required positive and negative evidence

- Positive: independently pinned exact content authority for all three roles; complete closures and deterministic digests; exact import order and actual module/assembly/command origins; validated library reuse; distinct-process admissions; and the discovery→baseline→Phase0→release→aggregate process/admission/reference chain.
- Negative: missing/wrong/self-derived caller pins; candidate/Profile/host/root/schema mismatch; duplicate/extra/missing/wrongly typed/prior/unknown fields; manifest, module, DLL, nested content, identity or dependency inventory drift; missing/unknown/duplicate/aliased/reparse/escaping paths; ambient autoload, preloaded/shadowed modules or commands, re-enabled autoload; wrong startup switch/config/session/wrapper/File operand; no-pin real SelfTest/LibraryOnly and forged/stale reuse; file/ancestor replacement windows and cross-process substitution; and omitted/tampered downstream admission. Every pre-import rejection records `import_attempts=0`; applicable loader failures also record marker count zero, child/Cargo count zero and formal root false. Use record mutations or synthetic fixtures; never alter installed files. If a required fence cannot be proven, report BLOCKED.

#### Supersedes / Superseded by

Supersedes only any implicit trust in installed PSHOME module content and the no-pin real-module SelfTest exception. All other D32 trust premises, frozen schemas not listed above, commands, gates and Stage Contract requirements remain in force.

---

### ADR-D32-POWERSHELL-MODULE-CONTENT-AUTHORITY-V2 — Protected runtime distribution and resolver admission

**Status:** APPROVED WITH CONDITIONS
**Decision authority:** GPT-6.1 Sol Max
**Decision date:** 2026-09-30
**Effective:** prospective only; no prior evidence is rebound
**Related milestone:** D32 final-gate readiness (D32-A-R2)
**Supersedes:** ADR-D32-POWERSHELL-MODULE-CONTENT-AUTHORITY-V1, only where this decision explicitly changes its proof method or V1 record type

#### Context

The V1 content pin and retained object handles do not alone prove that the actual managed and native resolvers are confined to those objects. A Win32 directory handle cannot freeze a complete namespace, and locking each directory against all creation is neither the proof nor the assumption. A valid module admission must bind a finite protected PowerShell distribution, its trusted-writer boundary, and the actual resolver inputs before the first installed module import.

#### Decision

1. The existing source/build trust premise does not implicitly authorize all installed PSHOME modules. The bounded base remains the trusted Windows OS, CLR, PowerShell Core and candidate-owned module-free bootstrap. This is not a hermetic-runtime claim.
2. A Coordinator independently supplies the exact path/SHA pin for a create-new, strict D32_POWERSHELL_MODULE_CONTENT_AUTHORITY_V2 schema-2 record. Its exact top-level fields are schema_version, authority_type, status, gate_authority, candidate_sha, source_repo, profile, powershell_host, powershell_root, distribution, resolver_policy, and modules. It binds the exact clean candidate SHA, canonical repository, Profile V2 path/SHA/bytes/opened identity, direct PowerShell host path/bytes/SHA/opened identity and PSHOME object identity. The generator is module-free and emits only an untrusted candidate; it cannot choose or grant its own caller pin.
3. The distribution binds the complete finite PSHOME tree: every directory and file, canonical path, bytes and SHA-256 for files, volume serial and 128-bit opened file ID, owner SID, exact security descriptor and its SHA-256, plus the protected directory ancestors and a deterministic complete inventory digest. Reparse points, aliases, incomplete enumeration, unknown trustees with effective write/replace/delete/rename/reparse/attribute/DACL/owner capability, or an untrusted owner are BLOCKED. The only trusted namespace writers are the explicitly listed machine maintainers (SYSTEM, TrustedInstaller and trusted elevated Administrators); an ordinary/current run token or an unknown trustee cannot declare itself trusted. The runner queries and records the current process token's elevation/integrity state, rejects high-integrity/system/elevated tokens and thread impersonation, and revalidates that token state on library reuse. No trusted maintenance may occur during admission. Unrelated additions outside resolver namespaces need not be forbidden; any possible PSHOME resolver candidate not in the pinned complete tree is rejected before use. An ancestor handle is only an object-identity witness: the ACL and path-specific namespace checks establish protection, not a share-mode lock over the whole directory.
4. The resolver policy binds only the exact PSHOME and Windows OS roots and a fixed resolver policy. Before imports, module-free inspection validates the current TPA list, dependency/runtimeconfig inputs, native search directories, startup-hook/profiling environment, loaded managed assembly locations and process-native module paths. User/CWD/PATH/ambient module paths and arbitrary external managed/native assembly sources are not trusted. PSModulePath is replaced with the exact pinned PSHOME Modules root and autoload is disabled. The current process configures safe native DLL search using the documented application-directory and System32 search locations; an API call by itself is not proof. External/preloaded native modules or an uninspectable resolver input fail closed before import.
5. Before the first module cmdlet/import, the direct fresh pinned pwsh.exe -NoProfile -File <current exact runner> startup and actual File operand, caller-owned Profile/content-authority/Git/candidate/repository pins and all cross-bindings are validated with module-free .NET/Core. The full distribution content, object identities, ACLs, ancestor paths and resolver state are checked and rechecked immediately before import. Retained handles witness identity and preserve admitted input bytes; protected ACL policy, not a whole-directory share lock, prevents ordinary writers from redirecting or replacing runtime inputs. Then, and only then, the fixed Management → Utility → CimCmdlets manifests may import. Actual module, assembly, effective command and native-module origins are checked. Library reuse and later phase boundaries revalidate authority references, content/ACL/object fences, autoload/PSModulePath, startup/process identity and resolver policy. Mutable globals, names or paths never manufacture admission.
6. Accepted startup remains the direct pinned host with -NoProfile -File and a finite documented switch set. -ConfigurationFile, command/encoded-command modes, wrappers, sessions, unknown/ambiguous switches and a wrong/relative File operand are rejected. A script cannot claim that its post-startup check prevented startup configuration or produced a zero pre-import marker.
7. The no-pin real-module SelfTest exception remains cancelled. Real SelfTest/LoaderSelfTest must pass Profile and content admission before imports; missing mode-required Git/Profile pins reject before imports. No-pin operations remain module-free bootstrap/schema/synthetic-negative checks with import_attempts=0; they cannot import modules, start children, run Cargo/network, claim a formal root or gate. Fact generators may emit untrusted candidates using only the module-free bootstrap.
8. Every producer embeds a strict shared D32_POWERSHELL_MODULE_ADMISSION_V2 schema-2 record in existing evidence. It binds the independently caller-pinned authority/Profile/Git references, actual runner process identity and non-elevated token state, startup/entry, full-distribution and protected-namespace digests, resolver policy/input digest, exact module closure/import order and actual module/assembly/command/native-origin verification. No per-run companion is introduced. All current producers, readers, validators, inline fixtures, nested references and gate readers reject V1, prior, unknown, missing, copied-as-own, stale or tampered admissions. Baseline V2 binds both the discovery admission and its distinct baseline-producer admission.
9. The outer D32 schema sequence remains fixture provenance V7, discovery V2, baseline V2, Phase0 matrix V8, release attestation V9 and aggregate V8. Profile V2, Trace V2, fixture manifest v3 and its six environment fields, bundle manifest v1, source/protoc/H7 authority V1, owner marker, failure-only blocked-diagnostic V1, D31 seeder provenance V2 and Host consumption remain unchanged. A future D31 companion must bind its own seeder process admission without changing Host consumption.
10. Required evidence includes exact full-distribution and ACL proof, resolver closure, fixed three-module import order/origins, library reuse, cross-process admissions and the complete discovery→baseline→Phase0→release→aggregate admission/reference chain. Negative evidence covers wrong/missing/self-derived pins; prior/extra/duplicate/wrongly typed schemas; content, identity, dependency or namespace drift; ambient autoload/PSModulePath, shadow commands/modules, reparse and startup injection; external managed/native/CWD/PATH resolution; unsafe owner/ACL/token/ancestor lifecycle; no-pin and forged/stale context reuse; cross-process substitution and downstream omission/tampering. Every pre-import rejection records import_attempts=0; applicable loader negatives also show marker/child/Cargo zero and formal root false. Mutations are synthetic/record-only; never modify installed files to test them.
11. The SC-D32-V1 sequence, exact argv/jobs/deadlines, five fixture phases, all suites/focused checks, V2 Job cleanup, fresh roots and quarantine scope remain unchanged. This decision authorizes no discovery, formal Phase0, root claim, release, canary, gate or D33 work. Implementation/no-Cargo evidence cannot produce D32 PASS or closure.

#### Frozen constraints and forbidden implementation

- Do not expand the fixed installed-module roles or accept ambient/external assemblies, arbitrary DLL helpers, machine-policy assumptions or a path/name/signature-only substitute for content authority.
- Do not rely on a blanket directory handle freeze. Do not mutate installed runtime files, ACLs or OS policy; install/mirror runtime files; alter real Codex/provider configuration; or change production/frozen authority.
- Preserve Profile V2, Trace V2, fixture manifest v3, all fixed argv/jobs/deadlines, D31 seeder V2, the full SC-D32-V1 gate and the D32-only stop boundary.

#### Supersedes / Superseded by

V2 supersedes V1's path-only PSHOME trust and blanket directory-share/namespace-freeze proof assumption, and replaces the external authority/admission record types with schema 2. It retains V1's independent caller pins, module-free-before-import ordering, fixed import roles, no-pin restrictions, downstream producer/consumer coverage and unchanged outer schema migrations. No prior evidence is rebound.

#### 2026-09-30 prospective Windows component and resolver clarification

This clarification is part of ADR V2 and does not create a new gate or change its APPROVED WITH CONDITIONS status.

1. The trusted Windows OS/CLR/Core premise is established by verified component identity, not by the `%SystemRoot%` string alone. The module-free runner binds `GetWindowsDirectoryW` to the process `SystemRoot`, opened volume/file identities, exact owner/security descriptors for the relevant resolver directories and ancestors, the current OS version, and exact opened identities/content/security descriptors for every current Windows native/managed resolver file referenced by the runtime inputs. The code-owned `MICROSOFT_WINDOWS_OS_INSTALLATION` record is finite and is not a blanket path, basename, or publisher-signature allowlist. Search remains limited to the admitted PSHOME application directory and protected System32 namespace; unknown external images are rejected before import.
2. `resolver_policy.os_security_components` is a strict mandatory ordered list: `MICROSOFT_WINDOWS_OS_INSTALLATION`, then `MICROSOFT_WINDOWS_DEFENDER_PLATFORM`. The latter binds the exact versioned Defender Platform root, root and ancestor opened identities/security descriptors, a complete finite file-and-directory inventory with bytes/hash/volume/file-ID/owner/SDDL/SD hash, deterministic complete inventory digest, and exact actual native image references. Its source proof binds matching product version and cache-only WinVerifyTrust-authenticated `MpOav.dll` and `MPCLIENT.DLL` publisher/issuer metadata. The Defender directory is not added to the ordinary native search path; only exact loaded Defender origins in this pinned component inventory are accepted. No post-load auto-expansion is allowed.
3. The existing `C:\ProgramData` ancestor is handled only by an exact-path ACL rule: SYSTEM must own it; untrusted ACEs may grant only the observed non-redirecting write-attributes/write-EA and unrelated-child creation bits. Delete-child, delete, rename, reparse, write-DACL, write-owner, or any other write capability is blocked. The existing protected `C:\ProgramData\Microsoft` child identity and descriptor remain bound; adding unrelated siblings cannot replace or redirect that child. This is an explicit narrow exception, not a general weakening of ancestor protection. A retained handle remains only an object-identity witness.
4. The signed and protected RTSS hook is not a Windows OS component. A fresh controlled runner must not reuse a process with RTSS code loaded. No publisher, basename, signature, or installation-path rule may exclude it or elevate it into the trusted resolver set. No Defender/configuration/AV exception is authorized.
5. Shared admission V2 now requires `resolver_admission.os_security_inventory_sha256` and complete exact `import_verification.native_modules` file references (source/component type, bytes, SHA-256, volume/file ID, owner SID and descriptor hash). Producer, reuse, reader and downstream context comparisons bind those exact references and the authority digest. V2 records lacking the new fields are prior/missing-proof records and reject; the outer migration sequence remains fixture provenance V7, discovery V2, baseline V2, Phase0 V8, release V9 and aggregate V8.

The 2026-09-30 fresh-process diagnostic after the specifically authorized exact RTSS process/helper exit observed the two Defender platform images and no RTSS hook, but it was a module-free pre-import census only. It is not module admission, formal D32 evidence, or a PASS. The required positive authority remains independently pinned for a new exact candidate SHA.

#### 2026-09-30 prospective exact local-volume-root clarification

This narrow clarification is prospective under ADR V2. It does not broaden the trusted writer set, installed components, resolver domain, authority schema, or any outer evidence version.

1. The V2 rule that unrelated additions outside resolver namespaces need not be forbidden includes one exact local-volume-root ancestor: the opened root of the same local volume that contains the independently caller-pinned current PowerShell host/Profile PSHOME. The root path, volume serial, opened 128-bit file ID, directory type, exact owner and full non-null/present/protected security descriptor are included in and compared through the pinned complete distribution's protected-ancestor inventory. A drive-letter spelling, caller Boolean, retained handle alone, or a root on another volume/UNC/nested path is insufficient.
2. At that root only, an untrusted effective `0x4` directory `FILE_ADD_SUBDIRECTORY` right may be tolerated. No `0x2` file creation/`FILE_ADD_FILE` (including file AppendData), metadata/EA, delete-child/delete, rename/replace, reparse, DACL/owner, `GENERIC_WRITE`, or `GENERIC_ALL` capability is permitted. Every existing child chain from that root to PSHOME and each protected resolver component must independently pass the existing opened-identity, owner, full-SD and ACL policy; a protected ancestor/root descriptor is not a substitute for protecting an existing child from delete/replace/redirect.
3. The volume root is not itself a managed/native/module resolver directory. Absolute pinned PSHOME and System32 roots, finite TPA/deps/runtimeconfig inputs, disabled ambient/CWD/PATH resolution, and exact pre-import origin reconciliation must establish that a newly created root sibling cannot become a resolver candidate. This policy is rechecked at admission and reuse; if any sibling or unknown image can enter a resolver, admission fails before import. The root exception cannot be transferred to PSHOME, ProgramData, another drive, UNC, or a nested Windows/runtime directory, and no sibling can become a Defender/OS component by ownership or name.
4. The ProgramData exception is separate and unchanged: its exact SYSTEM ownership, independently bound full descriptor and observed limited rights remain required, together with the exact protected existing `C:\ProgramData\Microsoft` child chain. ProgramData itself need not have its DACL marked protected; this does not weaken its bound ACL policy or grant it the volume-root `0x4` exception. No machine ACL/security configuration may be changed for this proof.
5. Required focused synthetic negatives cover wrong/missing/null/unprotected root descriptors, wrong owner/opened identity/path/type, 0x4 on files or non-root/resolver directories, other-drive/UNC/nested roots, all forbidden rights, unsafe child/ancestor replacement or inheritance, root siblings entering a resolver or masquerading as components, and ProgramData owner/descriptor/child-chain failures. Use record mutations and in-memory fixtures only; do not write to installed runtime paths or lock a whole volume.

The volume-root identity, full descriptor and child-chain/resolver proof are inputs to the same schema-2 authority and shared admission already defined by V2. There is no V3 record, per-run companion, outer migration, new gate or D32/D33 authorization.

## ADR-D32-BOUNDED-COMPILER-DIAGNOSTIC-V1 — One-shot bounded non-gating compiler diagnostic

- **Status:** APPROVED WITH CONDITIONS
- **Decision authority:** GPT-6.1 Sol Max
- **Decision date:** 2026-10-04
- **Related milestone:** D32 final-gate readiness (D32-A-R2)
- **Related implementation base:** `2de30edf5de48aa4ed3216c3d3df13c3e2f0ac51`
- **Supersedes:** None

#### Context

An earlier D32 inventory attempt retained a `D32_PHASE0_BLOCKED_DIAGNOSTIC_V1` record whose V2 process trace is `BLOCKED`. Its prior fetch completion was not retained, and its authority was `NONE`. This evidence cannot be upgraded into successful discovery or reused as authority for a later process. A separate, exact-candidate compiler diagnostic may help explain the failure, but it must remain outside the formal D32 evidence and gate path.

#### Decision

1. A future use requires a new create-new `D32_BOUNDED_COMPILER_DIAGNOSTIC_AUTHORITY_V1` record with `gate_authority = NONE`, exact candidate SHA/repository identity, six independently pinned source files (diagnostic runner, policy, selftest, fixture launcher, Profile V2 implementation, and module-authority implementation), exact Profile V2/module-authority/pinned-Git path and content pins, fixed command/environment/query list, current target and optional dependency-origin identities, external output/TempRoot owner identities, finite budgets, and optional image grants. Its path and SHA must be supplied independently; an authority candidate cannot authorize itself.
2. The only Cargo invocation is a direct, caller-pinned image with exact argv `test --manifest-path vita-agent/Cargo.toml --all-targets --locked --offline --features d32-a-test-helper --jobs 4 --no-run --message-format=json -vv`, from the exact clean Integration repository. At most one invocation is permitted. `--no-run` is mandatory: no test body, extra Cargo command, shell, profiler, root `rustc` probe, retry, fresh CargoHome, cache copy, or target override is authorized. The ordinary candidate-local `vita-agent/target` remains the exclusive target; it is neither a gate artifact nor a freshness/inventory claim.
3. The only optional dependency source is the existing `E:\d32\inv7\r\c` CargoHome. Current source provenance must be re-established from the exact current `vita-agent/Cargo.lock`, its six current manifest/lock pins and Profile V2 lock bindings, the independently pinned inv7 owner/blocked-attempt/raw-capture references, and current archive/pack/index/extracted-checkout contents. Registry archives are checked against lock checksums and strict USTAR members; Git objects are independently recomputed through commit/tree/blob closure and compared with the complete current checkout. `.git`, `.cargo-ok`, and Cargo checksum metadata are limited to the explicitly supported metadata cases. Unsupported formats, catalog drift, aliases, reparse entries, extras, missing members, symlinks/gitlinks, helpers, hooks, filters, alternates, promisor objects, submodules, user configuration, fetches, or repairs fail closed.
4. Source verification is bounded: each registry archive is at most 256 MiB; each Git pack is at most 256 MiB and index at most 64 MiB; each object is at most 64 MiB; object resolution is limited to 500,000 records and delta depth 32; expanded data is limited to 32 GiB; managed verifier buffers are limited to 512 MiB; the combined current registry/Git source proof is limited to 300 seconds. A bound or format failure is a diagnostic refusal/stop, not grounds to add a helper, install a parser, use network access, copy a cache, or expand Git authority.
5. Exactly five direct, pinned-Git metadata queries are permitted in this order: pre-Cargo `rev-parse --verify --end-of-options HEAD^{commit}`, `status --porcelain=v1 --untracked-files=all`, `ls-files -v -z`; then post-cleanup `rev-parse --verify --end-of-options HEAD^{commit}` and `status --porcelain=v1 --untracked-files=all`. No source-origin Git query, arbitrary query, or H7-C child extension is added. The bounded diagnostic route uses a finite query/join/pipe ceiling and refuses any other argv.
6. Existing Profile V2 VCTIP may be admitted only by its exact caller pin. Vendored protoc may be admitted only by a new, current-run grant bound to the exact lock-derived and content-verified dependency source/image. A prior inv7 protoc grant remains historical provenance only and cannot authorize the new diagnostic. No process may use old discovery permissions as a substitute for the new grant.
7. Before the one Cargo launch, require at least 8 logical CPUs, 12 GiB available physical memory, 8 GiB commit headroom, 200 GiB free on both output and ordinary-target volumes, and zero competing target writers. Any missing/unreliable measurement refuses launch. From the first owned launch, the total ceiling is 1,800 seconds, Cargo is limited to 1,200 seconds, and at least 120 seconds for cleanup plus 60 seconds for persistence must remain before launch. If that budget cannot be met, do not start Cargo. Resource sampling is no more frequent than once per 10 seconds; stop the owned Job on metrics unreliability, available physical memory below 4 GiB, commit headroom below 2 GiB, raw stdout/stderr reaching the shared 256 MiB cap, capacity/admission failure, or deadline. The sample sidecar has its own 64 MiB ceiling.
8. The direct Cargo root remains in the existing non-breakaway, kill-on-close Job and the existing V2 debugger. Every descendant CREATE still receives the unchanged parent/image/argv/identity/Job checks before `ContinueDebugEvent`; any executable under `vita-agent/target/debug/deps` is denied before continuation. At stop, Trace V2 remains `BLOCKED`, never a passing trace. The dedicated debug thread must be joined, retained handles signaled, debugger association absent, and Job active count verified at zero before close. Unverified cleanup permits no later launch.
9. New native measurement counters, 10-second process/system samples, raw stdout/stderr, Cargo JSON, and rustc/Cargo cross-binding are separate diagnostic result/sidecar data only. They do not add fields to Trace V2, change its accounting or event order, or authorize a formal cache result. Process attribution uses both PID and creation time; unmatched identities remain `UNVERIFIED`/unsampled, never guessed. Observed PrivateUsage is labeled a sampled maximum, not a lifetime peak.
10. The only result type is `D32_BOUNDED_COMPILER_DIAGNOSTIC_V1`, with `gate_authority = NONE`, `phase1_allowed = false`, and `aggregate_allowed = false`. Its only statuses are `COMPLETED_DIAGNOSTIC`, `BUDGET_STOPPED`, `REFUSED`, and `UNRESOLVED`; `PASS` is impossible. No formal Phase 0, Phase 1, aggregate, release, Host, D31 seeder, or readiness consumer may consume or promote this result. Existing `D32_PHASE0_BLOCKED_DIAGNOSTIC_V1`, SC-D32-V1, all formal outer schemas, fixed formal commands, and all Stage Contract gates remain unchanged.

#### Frozen constraints and forbidden implementation

- The historical inv7 attempt stays `BLOCKED`; missing historical fetch records stay `NOT_RETAINED`. Do not fabricate successful fetch records or re-label a blocked trace, grant, or gate authority.
- Output root and TempRoot are external to the repository and source CargoHome, independently pinned, create-new, owner-bound, and never reused. Do not reclaim or write inv7 evidence roots or owners.
- Do not change formal SC-D32-V1 commands, schemas, test inventories, cache policy, V2 Trace semantics, Job policy, Host authority, migration/recovery/security meaning, or frozen invariants.
- No Cargo/network/native diagnostic/source-closure invocation is authorized by this ADR alone. A future run requires the coordinator's separate exact-SHA pin and current complete caller inputs; generated facts remain untrusted until independently reviewed.
- This prospective diagnostic does not close a D32 gate, establish PASS/FROZEN, or authorize D33.

#### Required module-free implementation evidence

- Positive and negative tests for the exact authority/pin shapes, fixed Cargo argv/environment and five-query Git list, current-source-plan parsing, strict USTAR and in-process Git pack/index/tree/delta handling, stop/capacity/deadline policy, cleanup and test-executable denial, raw PID+creation sampling replay, all four non-PASS result statuses, historical `NOT_RETAINED`/`BLOCKED`/`NONE` replay, and exact formal-consumer schema rejection.
- Wrong/stale/cross-run pins, missing/extra source records, malformed archive/pack/index/tree, path/case collisions, unsupported source forms, wrong environment/target, arbitrary Git query, insufficient capacity/budget, unreliable sampling, capture ceiling, test-executable CREATE, cleanup failure, and any attempt to use diagnostic records as formal evidence must fail closed.
- Existing inv6/inv7 source records remain immutable and bound to their original attempts. Diagnostic-source relation is not a source-authority or gate claim.

#### Required real canary

None. This is not a formal gate or production canary.

#### Compatibility constraints

- Preserve Profile V2, module admission V2, process/Job Trace V2, fixture manifest v3, all formal outer schemas, fixed formal argv/jobs/deadlines, and the exact SC-D32-V1 order.
- Formal consumers remain strict on their existing Phase0 V8 / aggregate V8 and related exact schemas and reject the new diagnostic record as an unknown type.

#### Supersedes / Superseded by

Supersedes none. This decision only approves the prospective bounded diagnostic domain above and grants no formal authority.

#### 2026-10-04 historical-origin clarification

The earlier inv7 evidence remains a `BLOCKED` attempt with gate authority `NONE`; historical fetch completion is `NOT_RETAINED`, and absent fetch-record references are allowed to remain absent rather than being fabricated. The retained owner, blocked diagnostic, raw captures, and any old grant can support only a candidate/run/root origin relationship. Current source verification must independently reopen and compare the exact current lock, archives, Git object closure, checkout, and image grants. Before any such source-content read scan, the coordinator must independently pin the exact candidate, scripts, roots, records, file identities, and finite limits. This clarification changes no schema, gate, Stage Contract, or architecture status.

#### 2026-10-04 locked-source graph clarification — APPROVED WITH CONDITIONS

This implementation-only clarification closes how a current lock catalog maps to the source set needed by the fixed diagnostic. It grants no current source-content scan, diagnostic invocation, Cargo run, formal-gate authority, or reuse of historical discovery authority.

1. The lock parser emits `D32_BOUNDED_DIAGNOSTIC_LOCK_SOURCE_PLAN_V2`; the source-proof candidate and graph proof use semantics version 2. A V1 source plan or source-proof candidate cannot be relabeled or reused under these semantics. The complete `vita-agent/Cargo.lock` remains the audit catalog of locked package IDs, versions, source identities/checksums, immutable Git commits, and dependency edges; it is not by itself a claim that every lock entry is compiled.
2. The selected package is determined by the exact `vita-agent/Cargo.toml` package manifest, its default feature set plus `d32-a-test-helper`, and the fixed `--all-targets` command. This does not expand selection to every workspace member or every target triple. The only target/host pair is `x86_64-pc-windows-msvc`; because host equals target here, the same pinned platform facts apply to normal, build, and proc-macro dependency edges. Root dev dependencies are included for the selected package's all-targets run; dev dependencies of dependency packages are not treated as built edges.
3. The verifier traverses a finite dependency graph from that selected root. It checks each reached parent's complete supported dependency declarations against exact lock edges, including renamed packages, version constraints, source identity, selected-workspace path bindings, root workspace patches, and workspace-inherited dependency declarations. Every reached package requires its own current manifest bytes from an archive whose lock checksum and extracted-source inventory match, a manifest in a fully verified Git commit/tree/checkout, or an independently pinned current workspace manifest. Unknown source forms, missing reached manifests, ambiguous mappings, unsupported dependency fields, and unexplained edges block the proof.
4. Feature closure is deliberately conservative rather than a Cargo feature solver: optional dependencies and feature-activation edges are included unless the fixed target predicate is proven false. Only the finite pinned host/target facts are evaluated. Unknown target predicates are included conservatively or the proof is refused; they are never interpreted as false. All supported normal, build, proc-macro, and selected-root dev edges participate in the fixed point.
5. The proof emits an exhaustive partition of the full lock catalog: `INCLUDED`, `EXCLUDED_WITH_WITNESS`, or unresolved/refused before a complete proof is emitted. An included row carries a root path in the verified declaration graph and its exact source-manifest identity/digest. An excluded row carries a closed-reachability-cut witness covering the complete reachable-parent declaration set and confirms no active incoming edge from that set. Missing archive, checkout, or manifest content is never an exclusion reason; an absent package can be excluded only after the complete reachable graph independently proves it unreachable.
6. Registry archive verification, extracted-source comparison, Git pack/index/object/tree/checkout proof, current repository manifest pins, and the combined 300-second / 512-MiB source-proof bounds are unchanged. The proof remains module-free and in-process. No Cargo metadata, new Git root query, helper executable, network operation, fetch/copy, cache repair/write, config read, or source-origin expansion is introduced.
7. The source-proof candidate binds its current candidate SHA separately from the immutable historical inv7 origin SHA. Historical `BLOCKED` / `NOT_RETAINED` / `NONE` records continue to establish origin relation only, never current source authority. A completed candidate means only `CURRENT_SOURCE_CONTENT_VERIFIED_FOR_DIAGNOSTIC_ONLY`; it remains untrusted and cannot authorize a diagnostic run or become a formal trace/cache/checkpoint/PASS.
8. The fixed formal commands, V2 trace ordering, writer census, schemas, Stage Contract, and all existing gates remain unchanged. The only implementation evidence requested here is module-free L0 parsing, graph fixtures, source-plan/version rejection, edge/source/path reconciliation, root/target/feature selection, exhaustive witness and current/historical cross-binding negatives. Those tests do not substitute for a coordinator-pinned later source-proof invocation or any D32 gate.

### ADR-D32-BOUNDED-REGISTRY-TAR-FORMAT-V1 — Strict USTAR/GNU registry archive decoding and diagnostic census

- **Status:** APPROVED WITH CONDITIONS
- **Decision authority:** GPT-6.1 Sol Max (decision text forwarded by the Coordinator)
- **Decision date:** 2026-10-06
- **Related milestone:** D32 final-gate readiness (D32-A-R2)
- **Related implementation base:** `f3f017307e12828f965e1c80bb7614b30a29a3ad`
- **Supersedes:** Only the strict-USTAR-only registry archive format rule and directly dependent registry-content-proof/diagnostic record versions in ADR-D32-BOUNDED-COMPILER-DIAGNOSTIC-V1. All unrelated source trust, bounds, graph, Git, Cargo auxiliary metadata, process, formal-gate, and Stage Contract requirements remain unchanged.

#### Context

The bounded source-proof parser was intentionally USTAR-only. A later authorized one-shot source-proof run was blocked at a header-format validation failure. This decision narrowly adds an approved GNU regular-file/directory subset and a separate diagnostic-only archive-header census. It does not treat prior blocked runs as successful, infer that a run did not launch, prove any current cache contents, widen a trusted root, or permit another source-proof attempt by itself.

#### Decision

1. The single registry archive policy identifier is `D32_REGISTRY_TAR_USTAR_GNU_REGULAR_V1`. Every 512-byte member header is independently and exactly dispatched: USTAR requires magic bytes `757374617200` at 257–262 and version `3030` at 263–264; GNU requires magic `757374617220` and version `2000`. Mixed USTAR/GNU members in one archive are allowed. GNU bytes 345–511 are never treated as a USTAR prefix.
2. Common mode/uid/gid/size/mtime/checksum fields are strict unsigned octal: leading ASCII spaces only, then contiguous octal digits, then at least one NUL/space terminator and only NUL/space thereafter. All-zero/default fields remain valid. Reject signs, base-256, hidden digits, embedded terminators with following data, noncanonical encodings, and overflow. The unsigned checksum is the sum of all 512 header bytes with offsets 148–155 replaced by eight spaces. Fixed text fields use strict UTF-8; after the first NUL all remaining bytes must be zero. A GNU 100-byte name that fills its field without a NUL is valid.
3. USTAR prefix bytes 345–499 are strict UTF-8 text with NUL/zero padding; USTAR reserved bytes 500–511 must be zero. GNU fields are fixed: atime 345/12 and ctime 357/12 are strict nonnegative octal; multivolume offset 369/12 is zero; bytes 381/4 and 385/1 are zero; all four sparse offset/size pairs in bytes 386–481 are zero; continuation byte 482 is NUL; real size 483/12 is zero; and bytes 495–511 are zero. Linkname 157/100 is all zero, device numbers 329/8 and 337/8 are zero, and uname/gname fields at 265/32 and 297/32 obey strict UTF-8/NUL-zero-padding.
4. Only regular-file flags NUL and `0`, and directory flag `5` with zero data size, are accepted. GNU long-name/long-link `L`/`K`, PAX `x`/`g`, hard/symbolic links, sparse, multivolume, dump-directory, device, FIFO, contiguous and unknown types are rejected. Existing exact package-root path, canonical UTF-8/NFC, Windows namespace, alias, containment, collision, parent/type, size, padding, body/hash, two-zero-block, gzip framing, archive identity and lock-checksum rules remain unchanged. The package-root directory header may be absent or appear once as a size-zero directory. Parent directories may be inferred; a unique explicit directory record may later realize an inferred parent under the existing collision/type rules. Paths are rejected, never normalized or repaired.
5. Exact schema migrations for this registry-format dependency are: source-proof authority V2/schema 2; source-proof candidate V3/schema 3; `D32_BOUNDED_DIAGNOSTIC_REGISTRY_SOURCE_CONTENT_PROOF_V3`/schema 3; compiler-diagnostic authority V2/schema 2; and `D32_BOUNDED_COMPILER_DIAGNOSTIC_V2`/schema 2. Each binds the exact policy identifier. The registry proof binds every package's per-header inventory digest, header count, USTAR/GNU regular/directory counts, and source-content inventory through the proof digest; substitutions or old versions are rejected. `LOCK_SOURCE_PLAN_V2`, `GIT_SOURCE_CONTENT_PROOF_V2`, and `SOURCE_GRAPH_PROOF_V2` retain their current schemas and semantics. Historical source-proof attempts and outputs remain immutable and cannot be relabeled.
6. A separate future diagnostic census uses `D32_BOUNDED_DIAGNOSTIC_ARCHIVE_FORMAT_CENSUS_AUTHORITY_V1` and `D32_BOUNDED_DIAGNOSTIC_ARCHIVE_FORMAT_CENSUS_V1`. The strict authority binds the exact clean candidate, repository and origin identities, current lock/source-plan tuple, historical `BLOCKED`/`NOT_RETAINED`/`NONE` references, current code/profile/module-authority pins, finite unique archive references, run ID, output parent identity, and exact frozen bounds. Root IDs or untrusted metadata are not inferred from suffixes, names, or reused historical process evidence; any carried metadata must be independently reopened/pinned by the Coordinator. Missing catalog entries remain UNKNOWN and are not represented as covered.
7. The census opens only caller-pinned registry archives within the exact authorized cache root, verifies opened identity/bytes/SHA against current-lock checksums before header parsing, and uses in-process bounded gzip/tar streams. It hashes the compressed archive as required for lock/authority binding and records header inventory digest/counts/format counts. It reads and discards expanded member payload solely to reach subsequent framing; it does not hash, retain, extract, or treat payload as verified source content. It preserves per-archive coverage, unsupported set, first failing header offset/hash/reason when a header is at fault, and all unexamined references when a global stop occurs.
8. The census remains bounded to 300,000 ms and 512 MiB managed memory; per-archive compressed/expanded/member/count ceilings remain 256 MiB / 1 GiB / 128 MiB / 10,000; aggregate expanded/member limits remain 32 GiB / 1,000,000; output is at most 64 MiB. A bound stop is recorded and never resets time or permits retry/expansion. Result statuses are only `COMPLETE_DIAGNOSTIC`, `BLOCKED`, and `BUDGET_STOPPED`; COMPLETE requires all independently authorized references to be fully covered by supported headers and framing. An unsupported archive records the first failure and unknown remainder; other independent authorized archives may continue within the same aggregate bounds.
9. Census output explicitly carries `gate_authority = NONE`, formal Phase0/aggregate flags false, source-proof checkpoint false, diagnostic invocation authority NONE, formal-gate usability false, and payload-read-and-discarded true with payload hash/retention/extraction false. It is not source proof, cache authority, a build, compiler diagnostic, Phase0/Phase1, aggregate, canary, Gate, PASS or freeze evidence. Formal consumers keep their existing exact schemas and must reject both compiler-diagnostic V2 and archive-census V1.

#### Frozen constraints and forbidden implementation

- Preserve all unrelated ADR-D32-BOUNDED-COMPILER-DIAGNOSTIC-V1 constraints, the complete SC-D32-V1 sequence, formal schemas and gates, Profile V2, Trace V2, source-graph V2, Cargo auxiliary-file meanings, trust roots, Git authority and 300-second/512-MiB source-proof bounds.
- The only caller-pinned source roots remain unchanged. Do not expand a root, weaken identity/hash/checksum/reparse/path/collision checks, accept unsupported tar types, execute archive content, or read real Codex configuration, secrets, or credentials.
- No actual archive census or source-proof launch follows from this ADR. A later census requires its own create-new authority for the exact new clean candidate and independent Coordinator pinning of the authority path/SHA and all current refs. This ADR does not authorize a new SourceProofOnly attempt, compiler-diagnostic entry, Cargo/rustc/Git/helper/native process, network, fetch, cache write, or formal D32 work.
- A previous out-of-scope web lookup in the implementation work is recorded solely as a process deviation; it is not contract evidence or decision authority. No network research is needed to implement this byte-level contract.

#### Required module-free L0 implementation evidence

- Positive USTAR, GNU and mixed-per-member layout fixtures, including USTAR prefix and full-width GNU name, optional/unique root directory and inferred/explicit parents; identical semantic member inventories across layouts.
- Per-field GNU tail negatives for both times, multivolume, every reserved byte/span, all eight sparse numbers, continuation, real size and tail padding; common numeric/checksum/magic/version/text/NUL-padding/type/link/device/path/NFC/Windows namespace/containment/collision negatives.
- Exact source-proof producer-to-consumer roundtrip, archive header digest/count and four format-count crossbinding, whole inventory digest binding, strict JSON mutations, policy substitution, prior-schema rejection, header digest/count substitution, first primary-error preservation, and all-four-diagnostic-non-PASS semantics.
- Census authority/result strict-schema and JSON roundtrips; exact finite-pin/archive-set/root/bounds/output checks; supported, unsupported, blocked, budget-stopped and whole-unexamined coverage fixtures; header digest/count/format-count and coverage-digest mutations; no-auto-launch and formal-consumer rejection checks. Synthetic fixtures only; no real archive content is read for L0.

#### Required real canary

None. This is not a formal D32 gate or source-content canary.

#### Supersedes / Superseded by

Supersedes only ADR-D32-BOUNDED-COMPILER-DIAGNOSTIC-V1's strict USTAR-only registry archive format clause and the directly dependent registry-content-proof and diagnostic record versions listed above. Every other rule and gate remains in force. This decision authorizes no current census, SourceProofOnly run, compiler diagnostic, or formal execution.

### ADR-D32-BOUNDED-REGISTRY-TAR-GNU-LONGNAME-V1 — Strict bounded GNU L long-name records

- **Status:** APPROVED WITH CONDITIONS
- **Decision authority:** GPT-6.1 Sol Max (complete decision forwarded by the Coordinator)
- **Decision date:** 2026-10-06
- **Related milestone:** D32 final-gate readiness (D32-A-R2)
- **Related baseline:** `81a56e1129f368b8aa33d33391479399306fecd1`
- **Supersedes:** Only ADR-D32-BOUNDED-REGISTRY-TAR-FORMAT-V1's rejection of GNU `L` records, the directly dependent pathname/header-inventory binding, and the diagnostic record versions listed below. All other trust, source, budget, process, formal-gate, and Stage Contract requirements remain unchanged.

#### Context

The prior approved format policy was strictly USTAR/GNU ordinary files and directories and rejected GNU `L`. This was a conservative format boundary, not an implementation defect. The caller-pinned 2026-10-06 archive-format census retained 870 rows: 859 `COMPLETE_SUPPORTED`, 11 `UNSUPPORTED`, and no globally unexamined rows. Its 33,262 counted headers included 830 USTAR regular, 32,421 GNU regular, and 11 rejected headers. The 11 unsupported rows retained `remainder_unknown=true` and `framing_verified=false`; row presence does not prove the archives were complete. The census elapsed time was 70,640 ms. A reported 382,128,128-byte working set is not a managed-memory high-water measurement. The Coordinator's finite first-header diagnostics support a narrowly bounded path-control record, but do not establish any next header or later archive contents. The observed package names and 101–119-byte path samples are not an allow-list.

This decision allows one specific GNU `L` control-record subset and migrates only the records whose semantics change. It does not infer a clean or unlaunched prior attempt, make the old census complete, reuse its authority, prove current cache contents, expand any source root, or authorize another census/source-proof/diagnostic launch.

#### Decision

1. The new and sole registry archive policy identifier is `D32_REGISTRY_TAR_USTAR_GNU_LONGNAME_V1`. Every physical 512-byte header continues to be independently dispatched between the already approved strict USTAR and GNU layouts. All prior common numeric/checksum/text rules, GNU-tail restrictions, type rules, package-root containment, Windows namespace/alias/collision rules, body and padding checks, archive identity and lock checksum binding, two-zero-block termination, gzip/tar framing, and finite budgets remain in force.

2. The only new control header is GNU type byte `0x4c` (`L`), with the approved GNU magic `757374617220` and version `2000`; USTAR `L` is rejected. Its 100-byte name field must be exactly `././@LongLink` followed only by zero padding. Its linkname is all zero. The entire GNU tail, metadata, device, multivolume, reserved, sparse, continuation, real-size, numeric, checksum, and padding validation still applies to an `L` header. Its strict-octal size is the control payload size. The placeholder is not a filesystem member and never enters the ordinary filesystem-name set, source inventory, or extracted-source comparison. Repeated placeholders are allowed only on distinct valid physical `L` records. `K`, PAX `x/g`, links, sparse, multivolume, dump-directory, device, FIFO, contiguous, and unknown types remain rejected; no fallback parser is introduced.

3. The `L` payload contains only one effective path: size 2–4097 bytes; the last byte is exactly one NUL; preceding 1–4096 bytes are strict UTF-8. Interior/extra NUL, BOM, trailing payload, invalid UTF-8, non-NFC, unsafe Windows namespace, alias, or package-root escape is rejected without normalization or repair. A directory path may contain exactly one final `/`, and only a following directory header can validate it; then that one structural slash is removed from the effective path. A regular file may not use that slash, and repeated trailing slashes are rejected. The payload padding to the next 512-byte boundary must be all zero. No size, mode, uid/gid, mtime, link, source, or other attribute is parsed from the payload.

4. At most one bounded pending long-name payload exists per archive. Its only valid sequence is `none → one validated L → the physically adjacent next ordinary regular/directory header → none`. The next header offset must equal the checked sum of the `L` header, payload, and padding. Chained controls, intervening headers/extensions, terminator, EOF, truncation, unknown next type, and dangling pending controls reject. The pending control cannot propagate, cross archives, or be manufactured from caller/global state. Next-member type, size, and other metadata come only from that ordinary header. Each control payload is bounded to 4097 bytes; raw payloads are not accumulated or retained in output.

5. The control path is the unique effective path, and the following ordinary header must bind to it using exactly one accepted representation:

   - **Full exact:** GNU `name` or USTAR `prefix/name` exactly equals the same encoded path.
   - **Long-path truncation:** only when the effective path exceeds 100 UTF-8 bytes, a GNU name or a USTAR name with empty prefix may carry the exact first 100 raw bytes, or the longest valid UTF-8 scalar prefix using 99/100-byte capacity. Other truncation lengths, mismatches, nonzero padding, or a nonempty USTAR prefix combined with truncation are rejected.
   - **Explicit empty:** only for an effective path exceeding 100 bytes and only in GNU, the following name field may be all zero as a pair-bound omission; it is not an alternate path.

   A 100-byte raw field may split a UTF-8 scalar only in the exact pending-pair context and only when every raw byte matches that path projection. Those bytes are not decoded or used as a filesystem path. Without pending `L`, ordinary names retain strict UTF-8 validation. A nonempty USTAR prefix is accepted only for a complete exact path. `L` placeholders never stand in for the next member's name.

6. Only the effective ordinary member enters the existing package-root/relative-path inventory. Root-directory optionality, inferred parents and their unique explicit-directory realization, duplicate/case/type collisions, file-as-parent rejection, manifest capture and parsing, member body hashing, and extracted-source comparison remain unchanged and use the effective path—not the placeholder or short fallback. Every `L` header, its bounded payload and padding count toward expanded-byte and raw-header/member ceilings. Ordinary body bytes use the ordinary member's own size and are the only source-file body bytes. No new bound, timeout reset, cache copy, or aggregate raw-payload storage is permitted.

7. A deterministic pair inventory binds each accepted control and next header together, including: `L` offset/header SHA/size/control-payload SHA; next-header offset and SHA; ordinary format/type/size; raw name and bytes 345–499 field-slice digests; effective path and the exact fallback classification; and the ordinary inventory/content binding. The field-slice digest is not a pathname interpretation: under USTAR it accompanies the strict `prefix` parser, while GNU tail bytes are hashed only as raw header bytes and never treated as a prefix. The pair digest is deterministic in physical stream order. Header rows distinguish ordinary members and `GNU_LONGNAME_EXTENSION`; all `L` rows cross-bind to exactly one ordinary row. Reordering, omission, duplication, cross-pairing, fallback substitution, and cross-archive reuse fail closed. Four existing ordinary-format counts remain; add `gnu_longname_extension`, and require raw header count to equal the sum of all five. Also bind ordinary-header count, pair count, pair digest, long-name metadata count/bytes/digest. Inferred directories do not become raw headers or content members.

8. Strict schema migration is limited to directly affected diagnostic records:

   | Record | Previous | New |
   |---|---|---|
   | Source-proof authority | V2 / schema 2 | V3 / schema 3 |
   | Source-proof candidate | V3 / schema 3 | V4 / schema 4 |
   | Registry source-content proof | V3 / schema 3 | V4 / schema 4 |
   | Compiler-diagnostic authority | V2 / schema 2 | V3 / schema 3 |
   | Compiler-diagnostic result | V2 / schema 2 | V3 / schema 3 |
   | Archive-format census authority | V1 / schema 1 | V2 / schema 2 |
   | Archive-format census result | V1 / schema 1 | V2 / schema 2 |

   Every affected bootstrap, producer, reader, validator, failure constructor, JSON roundtrip, and fixture binds the new policy and strict exact shape. Old/unknown versions, old policy, missing/extra/duplicate/wrong-type fields, and count/digest/pair substitutions reject. `LOCK_SOURCE_PLAN_V2`, `SOURCE_GRAPH_PROOF_V2`, `GIT_SOURCE_CONTENT_PROOF_V2`, and `source_plan_semantics_version=2` remain unchanged. Formal D32 schemas and SC-D32-V1 are not migrated; they continue to reject diagnostic-only records.

9. A future census may hash the bounded `L` control metadata only to validate the path/pair/framing diagnostics. Ordinary source-file payload continues to be read/discarded without hashing, retention, or extraction. The new census result distinguishes ordinary payload flags from long-name metadata count/bytes/digest and never outputs raw control payload or ordinary body bytes. Census result statuses remain exactly `COMPLETE_DIAGNOSTIC`, `BLOCKED`, and `BUDGET_STOPPED`; `gate_authority=NONE`, formal Phase 0/aggregate flags false, source-proof checkpoint false, diagnostic invocation authority `NONE`, and formal-gate usability false. Complete requires all authorized archives and all pair/framing validation to complete as supported.

   Implementation proceeds as one schema/parser/test batch, then a new clean exact candidate, then a separate create-new V2 census authority and independently pinned current references. The census must be rerun for its complete authorized set; old 859 rows may not be combined with a later 11-row scan. A census does not authorize source proof. Any later source proof requires its own new authority and explicit execution authorization, and does not automatically authorize Cargo.

#### Frozen bounds, unknowns, and forbidden actions

- Preserve all existing source roots and the existing 300,000 ms combined budget, 512 MiB managed cap, 256 MiB compressed archive bound, 1 GiB per-archive expanded bound, 128 MiB ordinary member bound, 10,000 raw headers per archive, 32 GiB aggregate expanded bound, 1,000,000 aggregate raw headers, and 64 MiB output limit. All checked arithmetic and stop/remainder semantics remain fail-closed.
- Keep the prior `3eba2f3e160543b2b645c82bd016640d` census and its 11 unknown-remainder rows immutable. A prior `.Contains` type error caused a duplicate read of the same 11-row set; it is preserved in the attempt ledger but is not additional coverage, a second authority, or archive proof. Never concatenate that duplicate with existing rows.
- The 153 missing catalog entries, 11 archives' subsequent content/framing, Git closure, complete source graph, and whether a future combined run can finish within existing budgets remain UNKNOWN.
- No current census, SourceProofOnly run, compiler-diagnostic entry, Cargo/rustc/Git/helper/native process, network, fetch, cache write, or formal D32 execution is authorized by this decision. D32 remains NOT FROZEN, Gate NONE, and no D33 transition is authorized.

#### Required module-free L0 evidence

Use synthetic bytes and record mutations only; do not read real inv7 archive/cache contents. One integrated suite must cover positive ordinary USTAR/GNU/mixed layouts; multiple L pairs and placeholder reuse; Unicode and directory forms; every exact fallback including raw 100-byte split-scalar, 99/100 scalar-boundary, full exact and GNU empty representation; optional root/inferred/explicit parents and equivalent semantic inventories. Negative tests must cover header magic/version/checksum/tail and malformed placeholder, all payload length/NUL/BOM/UTF-8/NFC/path/padding cases, unsupported or nonadjacent/chain/dangling pairs, next-kind/size mismatch, truncation, fallback/prefix disagreement, collisions/aliases, and cross-archive/state reuse. Bind and mutate pair/header/control-payload/inventory digests and raw/ordinary/pair counts through actual producer → strict validator → serialized JSON readback → consumer paths. Verify old schema/policy refusal, all census statuses/remainder and budget stops, ordinary payload discard versus control-metadata hashing, primary error retention, no-auto-launch, formal-consumer refusal, and exact source/header/resource bounds. No real archive content, Cargo, child process, network, fetch, or cache write may be used.

#### Required real canary

None. A future diagnostic census is separately authorized and remains non-gating; this decision provides no source-content or formal D32 canary.

#### Supersedes / Superseded by

Supersedes only the prior registry-format decision's strict rejection of GNU `L`, the affected path/header-inventory binding, and the listed diagnostic schemas. Every other source-trust root, source-plan/graph/Git rule, Cargo auxiliary-file meaning, Profile V2/Trace V2/SC-D32-V1 contract, budget, formal consumer, and D32 gate remains unchanged. This decision grants no current census, source proof, compiler diagnostic, or formal execution.

## ADR-D32-BOUNDED-SOURCEPROOF-LIFECYCLE-V1 — bounded SourceProof lifecycle and durable supervisor

**Status:** APPROVED WITH CONDITIONS
**Decision authority:** GPT-6.1 Sol Max
**Decision date:** 2026-10-06
**Related milestone:** D32
**Related baseline:** `de398b823bb8ea292ab9773bc761d4950a4addae` (read-only verified clean Integration candidate)

### Scope and supersession

This decision governs timing, owned-process supervision, termination, cleanup audit, and future execution authority for standalone `SourceProofOnly`. It supersedes only the prior bounded-diagnostic ADR's ambiguity about standalone source-proof timing boundaries and the temporary outer-wrapper execution method. It does not authorize implementation, probe, census, source-proof, Cargo, or any other launch by itself.

### Context and historical evidence

The reader's existing stopwatch starts after parameter binding at reader entry. It does not account for earlier process creation/controller admission or later outer termination and cleanup. Deadline checks within source streams, manifests, graphs, and Git are necessary, but cannot hard-interrupt synchronous OS I/O, JSON serialization, or persistence, or guarantee cleanup and records finish at a deadline.

Reject the interpretation that termination, cleanup, and persistence must take zero time at 300000 ms. The 300000 ms proof limit must not thereby become 360000 ms of source-work permission.

- The Coordinator-reported `fe4085` outer stop at approximately 300055 ms with no result remains a consumed attempt; its 55 ms controller lateness proves neither an internal deadline failure nor source closure.
- The Coordinator-reported `af919` outer kill at 270000 ms, which removed the finalization reserve, remains an execution deviation. It does not prove that the inner reserve or deadline implementation failed.
- The later `de398` preparation is not execution authority; an unlaunched preparation is neither consumed nor successful.
- Actual child phase, the 153 missing entries, Git closure, and source-graph closure remain UNKNOWN. Prior format census is not a source-proof checkpoint.

### Fixed lifecycle clock

The timing policy is `D32_SOURCEPROOF_LIFECYCLE_V1`.

| Interval from the same monotonic `T0` | Permitted work |
|---|---|
| `[0, 270000 ms)` | Admission and all current-source/proof work |
| `[270000, 300000 ms)` | Finalize already-complete proof, persist its result, and normal process exit/cleanup only |
| `[300000, 345000 ms)` | Terminate owned process, bounded join, verify cleanup, and finite audit capture only |
| `[345000, 360000 ms)` | Persist finite terminal-audit metadata only; do not wait for proof completion |
| `>=360000 ms` | This attempt's management authority expires; incomplete facts remain UNVERIFIED/UNRESOLVED |

This is a 300-second proof-permission window plus a separate 60-second cleanup/audit-only reserve. It is not 360 seconds of source-work budget and is not a physical promise that eliminates OS/scheduler lateness.

Every boundary uses the same monotonic counter's raw ticks with checked arithmetic; a boundary value is expired. UTC is an audit label only. Missing, backward, overflowing, or mismatched counter/frequency bindings fail closed.

### `T0`, admission, and cross-process clock

`T0` is captured before this attempt's durable-controller admission and before its first owned launch. Process creation, startup, parameter binding, authority/profile/code-pin admission all consume the same window.

If a controller host is created specifically for this attempt, its caller captures and passes the shared clock context before that creation call. The controller may not reset the 300-second budget at its own entry. When the controller runs in an already trusted host, it captures the counter at the boundary above.

Independent pin preparation may precede the attempt; actual current-source verification, origin verification, and closure work may not be moved outside the timed window.

Clock context binds timing policy, candidate, execution authority, run/owner, actual controller/reader PID plus creation identity, counter origin/frequency, and all absolute deadlines. The reader uses those shared deadlines; it may not calculate a new budget from its own entry time. Existing V4 `proof_elapsed_milliseconds` is not relabeled as the outer total. The separate execution record reports the shared window and reader-entry offset. Stdout markers do not establish clock context.

### 270-second work cutoff

All registry/Git/source-content reads, manifest/lock parsing, source-plan/graph construction, origin revalidation, closure checks, and canonical proof inventories/digests must finish before 270000 ms.

At and after the work cutoff:

- Do not start or continue source, cache, Git-object, manifest/lock, or code-pin content reads.
- Do not add packages, edges, witnesses, inventory, or missing proof content.
- Bytes returned late from in-flight I/O must not be parsed, hashed, merged, or used to claim proof; discard them and record failure only.
- Check the shared deadline before and after blocking operations and bounded chunks; an operation started before expiry receives no late-completion exemption.

At 270000 ms the supervisor observes a cooperative work-stop/advisory boundary; it does not automatically kill the reader. It must not remove the remaining 30-second finalization window merely because work time ended. Other explicit safety violations may stop immediately.

### 30-second finalization and 300-second expiry

Within `[270000, 300000 ms)`, permit only exact-shape checks on an already closed, bounded record, pure record-consistency validation, JSON serialization, create-new write/flush, artifact identity/hash binding, and normal process exit/owned cleanup. Pure-record validation may not construct proof, reread sources, or relabel incomplete graph/content work as finalization.

The complete SOURCE_PROOF candidate and its required bindings must be durably persisted before 300000 ms. After expiry, do not finish or rewrite a candidate, append success fields, rewrite partial output, or create a new successful candidate.

At 300000 ms all reader proof/finalization authority expires. At the first executable observation, the controller requests termination of the still-active or not-yet-verified owned process/Job. The reserve is derived from fixed `T0`, never restarted from a late observation or kill time. After expiry, only exact owned Job/process stop, retained-handle bounded wait/join, actual exit/Job/capture-worker/handle lifecycle checks, draining capped already-buffered advisory/error data, and finite cleanup/terminal-audit metadata are allowed.

No source/code/cache reads, candidate-content reads or hashes, closure derivation, compiler/Git/helper launch, source repair, or new proof authority is allowed after expiry. If cleanup remains unverified at 345000 ms, do not extend the join: record UNVERIFIED, apply the fixed kill-on-close fail-safe, and proceed to terminal audit. If the audit is not fully submitted by 360000 ms, remain UNRESOLVED; do not wait indefinitely, retry, or rewrite merely to finish it.

Terminal audit may preserve only a bounded snapshot of facts already established before its relevant deadline; it cannot first establish source proof success in the reserve. It always has `gate_authority=NONE` and grants no launch permission.

### Durable controller and process ownership

Add a version-controlled, module-free durable controller at `scripts/d32-bounded-diagnostic-sourceproof-controller.ps1`. The fixed minimum source-pin closure is that controller plus the existing five source-proof source files. An authority-provided arbitrary script set cannot replace the closure; no additional native executable/helper is introduced.

The controller must provide:

- Exactly one reader creation attempt; a failed create attempt still consumes that execution attempt.
- Exact pinned PowerShell image, fixed SourceProofOnly entry/argv/environment; no shell, custom command, or extra child.
- Retained process handle and PID plus creation identity; never kill by name, ambiguous PID, or global process list.
- An independent non-breakaway, kill-on-close Job before reader execution; failed assignment/admission must not continue to run.
- Job/process ownership coverage independent of stdout markers; `.Kill()` returning is not cleanup proof.
- Deadline supervision that cannot be blocked by reader synchronous I/O, stdout/stderr draining, or controller result writes.
- Owned-reader fail-safe on caller interruption/controller failure. Unknown ownership/cleanup may not be overridden by a `finally` block or exit code 0.

Implementation may reuse existing pinned in-process ownership facilities. Do not change formal Trace V2 or introduce a trace exception/field.

### Schema and execution authority

Keep all approved GNU long-name policy/schemas unchanged:

- `D32_REGISTRY_TAR_USTAR_GNU_LONGNAME_V1`
- SourceProof authority V3, candidate V4, registry proof V4
- Compiler diagnostic authority/result V3
- Census authority/result V2
- Source-plan, source-graph, and Git proof V2

Do not smuggle lifecycle fields into those exact records. Add two separate strict records:

- `D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_EXECUTION_AUTHORITY_V1`
- `D32_BOUNDED_DIAGNOSTIC_SOURCE_PROOF_EXECUTION_V1`

The execution authority is independently caller-pinned and binds exact clean candidate/repository identity and unique run/owner; the unchanged inner SourceProof authority's canonical path/bytes/SHA/file identity; Profile/runtime; the fixed six-file closure and invocation roles; create-new candidate/audit/journal paths and parent identities; fixed timing policy, deadlines, and finite output/buffer limits. Its SHA comes only from the independent caller; self-authority, self-declared SHA, arbitrary budgets, and free argv are forbidden.

The execution result exact-shape binds authority refs, actual source/runtime pins, the shared clock, actual launch/PID/creation/Job identity, observed phase deadlines and exit time, candidate artifact state, stop/cleanup facts, primary/secondary errors and lateness/overshoot. It has no status outside `COMPLETED_DIAGNOSTIC_ONLY`, `BUDGET_STOPPED`, `REFUSED`, or `UNRESOLVED`.

Reject missing, extra, duplicate, wrong-type, old/unknown policy, or cross-candidate/run/authority/process/artifact fields. If candidate V4 has no `run_id`, bind the run through its exact inner-authority reference; do not add a synthetic field.

The new audit record and journal are each limited to 64 KiB and retain no source or raw control payload. Existing progress stdout cap (16000 bytes), candidate cap (64 MiB), and verifier managed-buffer cap (512 MiB) remain unchanged; the controller receives no additional same-sized buffer budget.

### Status and evidence use

- `COMPLETED_DIAGNOSTIC_ONLY`: all proof work finished before 270 seconds; candidate persistence/required bindings, reader exit, and owned cleanup were verified before 300 seconds. Only persistence of that fact snapshot may follow.
- `BUDGET_STOPPED`: work/proof window expired; the stop cause is known and no candidate may be promoted.
- `REFUSED`: reader was not started; admission rejected and recorded.
- `UNRESOLVED`: ownership, timing, output submission, cleanup, or evidence chain has an unverified part.

`ProcessExited=true`, exit code 0, a file's existence, a success marker, or the legacy `CURRENT_SOURCE_CONTENT_VERIFIED_FOR_DIAGNOSTIC_ONLY` string cannot override expiry/unknowns.

Each late observation, termination request, exit, join, or flush records its scheduled boundary, observed tick, and lateness. Calls crossing a boundary record their actual duration; they cannot claim the total ceiling was met or turn lateness into source-work permission.

Absent, partial, or unconfirmed candidate output remains unchanged; do not delete, overwrite, or reuse that path. Cleanup and evidence availability are distinct: cleanup after timeout is not proof success.

Future diagnostic preparation may jointly review and independently pin the unchanged V4 candidate plus this execution record. Candidate alone or a missing/non-complete execution record cannot be promoted. The audit is not a formal checkpoint, PASS, gate, or Cargo launch authority.

### Required implementation validation and future L1

One integrated synthetic L0 batch must use synthetic records, fake monotonic clocks, and bounded replay to cover:

- 269999/270000/299999/300000 and 345000/360000 boundaries.
- 270-second advisory without kill, 300-second expiry, and non-resetting reserve.
- Startup/admission time consumption, child clock reset rejection, counter overflow/rollback.
- Late in-flight reads, late finalization, partial candidate write.
- Late exit 0, deadline/exit race, stderr/marker failure.
- Kill/join/Job count/ownership/PID reuse and controller interruption.
- Audit write failure/overshoot and primary-error preservation.
- New authority/result producer → validator → JSON readback → consumer closure.
- Missing companion, cross-run/pin, auto-retry, late-success, and formal-consumer rejection.

L0 does not prove real Job/termination behavior. A changed controller launch boundary requires a separately authorized minimal L1 admission under the effective execution-efficiency policy. Do not use the first real source scan as a trial run; without a legal short, real, non-source-content validation path, remain NOT VERIFIED at admission.

After the implementation batch and clean new candidate, the Coordinator may prepare a new independent execution authority, inner SourceProof authority, run/output/pins and explicit one-shot execution authorization. Existing preparations, old authorities, old census, and this ADR cannot launch the attempt. The existing candidate-bound census requirement is not reduced. One fixed source-proof attempt only: no automatic retry/resume/checkpoint concatenation or budget increase. Unverified cleanup blocks later related launch until a separately authorized exact cleanup check; read-only investigation remains possible.

### Invariants retained and remaining UNKNOWN

SC-D32-V1, formal commands/tests/gates, Profile V2, Trace V2, cache/source trust, GNU parsing semantics, and the 1800-second compiler diagnostic budget are unchanged. This ADR does not migrate census timing or authorize its execution.

Archive-format support is not source closure. The 153 missing entries, Git/source graph, whether actual work fits within 270 seconds, and real controller cleanup remain UNKNOWN.

D32 remains NOT FROZEN with Gate NONE. This decision itself authorizes no implementation/build/helper/native probe, archive/cache additional reads, Cargo/Git/source-proof/census/network or other launch. No D33 is established.

## ADR-D32-BOUNDED-SOURCEPROOF-NON-SOURCE-L1-V1 — Isolated short non-source lifecycle validation

**Status:** APPROVED WITH CONDITIONS — implementation contract only

**Decision authority:** GPT-6.1 Sol Max

**Decision date:** 2026-10-06

**Related milestone:** D32

**Related baseline:** `d95b08f431bfb4befc03a5118a4b05ad019cc709` (clean, read-only verified)

**Baseline controller SHA-256:** `6f3dd8068035f3584a8c097554dcd8436e4687c36d76b4c010b026e30688baed`

**Baseline reader entry SHA-256:** `dc7b7d213280fc44b9f6ec2d104ab23d70dcc0af95142117b2d5c0db0763acd4`

This decision closes only the minimal non-source lifecycle-validation path required by `ADR-D32-BOUNDED-SOURCEPROOF-LIFECYCLE-V1`. It does not alter SourceProof timing, GNU archive policy/schema, SC-D32-V1, or any formal gate. It does not authorize a probe or launch.

### 1. Isolated mode and fixed code closure

Add a mutually exclusive `NON_SOURCE_L1` parameter set to the existing controller and `scripts/d32-bounded-diagnostic-sourceproof.ps1`. Do not add a fixture executable, arbitrary script path, free command, shell, extra observer, or helper process.

Retain and independently pin exactly the existing six-file closure:

1. SourceProof controller
2. SourceProof entry
3. compiler-diagnostic runner
4. compiler-diagnostic policy
5. build-toolchain-profile implementation
6. PowerShell module-authority implementation

The reader's L1 branch must be selected and explicitly terminate before any SourceProofOnly runner call, source-proof authority/Profile/source-origin handling, or fall-through. Mixed parameters, unknown modes, or a wrong authority type are refused.

Both actual launch cases reuse the same native creation, suspended admission, Job, retained-handle, capture/join, and cleanup implementation as SourceProofOnly. Do not copy a looser launcher for L1. Only purpose, fixed fixture behavior, record type, and short deadlines differ.

### 2. Allowed and prohibited reads

L1 may read only:

- the independent caller-pinned L1 authority;
- the six fixed code pins;
- the fixed Program Files PowerShell 7 runtime and protected inputs required for runtime admission;
- its own bounded L1 records.

Code-pin reads are not application-source investigation. Do not read application source, Cargo manifests/locks, `.git`, inv7 or other cache/source content, or real user Codex/Git/Cargo/provider/shell configuration.

Do not require an inner SourceProof authority, dependency-origin, or current-lock binding. The L1 runtime reference is independent and caller-provided; do not call full Profile validation in a way that indirectly reads manifests or locks.

Do not add compilation, build, or compiler processes or generate a fixture binary. Reuse only the existing module-free native-surface initialization permission; do not expand it to an external compiler, helper, or new native image. The reader fixture performs fixed managed behavior only and does not load SourceProof implementation.

### 3. The only fixed validation batch

One authority, one controller invocation, and exactly three ordered cases, with at most two reader `CreateProcess` attempts:

| Case | Fixed behavior | Expected native creation |
| --- | --- | ---: |
| `NORMAL_EXIT` | Emit bounded stdout/stderr and identity token, exit 0, verify ordinary cleanup | 1 |
| `FORCED_OWNED_TERMINATION` | Emit ready token, perform a finite wait; controller sends exactly one planned termination to the exact owned Job and verifies cleanup | 1 |
| `ENTRY_PIN_BINDING_REFUSAL` | Run real pre-create pin validation for the fixed reader entry with an internally derived single-SHA mismatch; confirm refusal before `CreateProcess` | 0 |

The third case is the binding negative; do **not** add a real controller-kill/abrupt-owner-abort case. Owner-abort L0 and kill-on-close configuration checks remain. The L1 record explicitly says abrupt owner abort is `NOT_RUN`, and no wider coverage claim is permitted.

Derive the negative reference only within that fixed case from the correct entry reference by changing one predefined SHA bit. Keep path, identity target, and all other fields unchanged. Do not write a bad script, tamper with runtime/authority, accept a caller-supplied bad path/command, or merely compare preset strings: traverse the actual shared opened-handle pre-create validation.

### 4. Short deadlines and stop rules

Use the independent policy `D32_SOURCEPROOF_NON_SOURCE_L1_V1`:

- The whole batch starts at one shared monotonic `BatchT0` and lasts at most 60,000 ms, including admission, initialization, launches, cleanup, and records.
- Each case starts from its `CaseT0` captured before admission and is bounded by: active/admission/fixture 5,000 ms; owned termination/cleanup 10,000 ms; audit and case completion 15,000 ms.
- No case may exceed the absolute batch deadline. A deadline is an upper bound, not a required wait; advance immediately on completion. All clocks, checked arithmetic, lateness, and cross-process bindings follow LIFECYCLE principles and may not reset.
- Fixture waits have finite termination; no infinite sleep. Natural exit cannot stand in for a successful forced-termination case.
- Each actual case has one creation attempt; failure consumes it. Case two permits at most one planned termination request. Safety fail-safe termination is recorded separately and cannot impersonate planned success or trigger retry.

If ownership or cleanup is unknown, stop the batch and all later native creation; do not start SourceProof, census, Cargo, or another related execution. If cleanup is verified but an ordinary validation fails, finish remaining fixed cases within the same authority and remaining budget for a batched blocker report; never rerun a failed case.

Short deadlines validate only the native boundary. They cannot be labeled as proof of the real 300-second SourceProof expiry, source-budget sufficiency, or source closure. Real timing semantics remain covered by required fake-clock L0.

### 5. Runtime, argv, environment, and fixture

Use only the independently pinned runtime:

`<fixed drive>:\Program Files\PowerShell\7\pwsh.exe`

The controller and reader actual image must match the same canonical runtime reference and retain existing version, 64-bit, namespace, identity, and runtime-admission rules. Do not resolve through PATH, copy a tool image, or substitute another PowerShell.

The fixed reader argv begins:

`-NoLogo -NoProfile -NonInteractive -File <fixed reader entry> -NonSourceL1`

Only fixed roles may follow: L1 authority path/independent SHA, batch/case IDs, the unique nonce, and controller-bound clock context. No SourceProofAuthority, Profile, origin, custom script/command, duration, or budget override is accepted.

Use a fresh, external, owner-bound L1 root as working directory, not the repository or source/cache root. Use a fixed environment allowlist without inheriting the parent environment:

- existing SystemRoot/WINDIR, constrained PATH, and PSHOME module path;
- module autoload disabled and telemetry opt-out;
- TEMP/TMP and user directory/config/cache variables redirected to this run's L1 root.

User-directory redirection is a fixed enumerated set of variables and root-derived values; the authority cannot supply an arbitrary environment dictionary. Protected Program Files/Windows runtime inputs do not grant access to real user configuration.

The fixture may emit only bounded fixed tokens/diagnostics and perform a finite managed wait. It must not enumerate files, read application content, use network, create children, import modules, allocate large payloads, or emit SourceProof records. Stdout is a behavior token, not process-ownership authority.

### 6. Required actual identity and cleanup evidence

For both actual cases, verify:

- current candidate, controller/entry code, and runtime opened-handle pins;
- exact argv/environment and case/batch/nonce binding;
- retained native process handle, PID, and creation identity;
- actual process image bound to the caller-pinned executable;
- suspended creation → Job assignment/admission → resume order;
- independent non-breakaway, kill-on-close Job with exactly one reader;
- exit observed through the retained handle;
- Job active count zero and Job process accounting consistent with the sole reader;
- stdout/stderr capture completion and joined threads;
- deterministic closure of Job/process/thread/pipe/admission handles, with failures recorded.

Terminate only through the retained owned Job/process. Do not use names, global enumeration, or ambiguous PID. `.Kill()`, a `TerminateJobObject` return, exit code 0, or a token alone cannot replace the required checks.

The normal case expects no planned termination. The forced case must prove the request occurred while the fixture was active and observe its corresponding exit. Lost capture, truncation, identity mismatch, unreliable Job accounting, or unverified cleanup cannot produce a completed status.

Do not expand formal Trace V2, introduce a CREATE exception, or claim whole-process formal-gate completion.

### 7. Independent fixture authority and result

Add exactly these strict records:

- `D32_BOUNDED_SOURCEPROOF_NON_SOURCE_L1_AUTHORITY_V1`
- `D32_BOUNDED_SOURCEPROOF_NON_SOURCE_L1_V1`

Both use `schema_version = 1`, fixed purpose `NATIVE_LIFECYCLE_VALIDATION_ONLY`, policy `D32_SOURCEPROOF_NON_SOURCE_L1_V1`, and `gate_authority = NONE`.

The authority exact shape binds the clean current candidate, canonical repository identity, batch/run/owner, six fixed file pins, independent runtime reference, three ordered cases and expected creation counts, unique nonces, fixed argv/environment policies, a fresh owner-bound L1 root and create-new record/journal paths with parent identities, finite limits, and issue time. It accepts no SourceProof authority/reference/output path, free case list, free argv, extra fixture file, or configurable deadline. Only the independent caller supplies its SHA; an authority candidate cannot authorize itself.

The result binds authority/current code/runtime pins, actual invocation, shared and per-case clocks, native attempts/identities/Job facts, capture summaries, exit/termination/cleanup, primary/secondary errors, observed lateness, and all executed/unexecuted cases. A negative case with no native attempt cannot fabricate PID/Job/cleanup evidence. Reject missing/extra/duplicate/wrong-type/unknown-version/policy and cross-candidate/run/case/nonce/process/artifact combinations.

Do not change SourceProof execution authority/result V1 or GNU-related schemas. Their strict consumers must reject the L1 types; never translate the short fixture budget into real SourceProof authority.

### 8. Bounded output, states, and submission confirmation

L1-owned buffers are capped at 16 MiB; the fixture holds no large payload. Existing runtime initialization is not relabeled as buffer peak or working-set evidence and the SourceProof 512 MiB cap is unchanged. Each stream retains the 16,000-byte hard cap and expected fixture output is at most 1,024 bytes. Batch result and journal are each at most 64 KiB and contain no source or raw fixture authority content. All outputs are create-new; never delete, overwrite, or reuse a failed path.

Batch statuses are exactly:

- `COMPLETE_NON_SOURCE_L1`
- `BLOCKED`
- `BUDGET_STOPPED`
- `REFUSED`
- `UNRESOLVED`

Case statuses distinguish verified actual native boundary, verified expected refusal, and failure/unknown. Completion requires both actual cases fully verified, the third actual refusal with zero creation, and all records/submission/caller return within deadlines. Reuse execution-record persisted-fact and caller reconciliation principles: a pre-flush snapshot is not proof of submission. The final journal fact binds result path/bytes/SHA/file identity and observed submission time. Missing, partial, late return, or unverified submission is unresolved. The result cannot attest its own post-flush completion.

Every result fixes: source-proof checkpoint false; source closure not established; diagnostic invocation authority `NONE`; formal gate usability false; formal phase and aggregate allowed flags false.

### 9. Minimal validation and future joint admission

Do one integrated implementation/L0 batch covering mode mutual exclusion, rejection between both authority domains, fixed cases/argv/environment, deadlines/bounds, zero-create refusal, identity/capture/cleanup failures, record submission, and producer → strict validator → JSON → consumer closure. Reuse existing clock/ownership negatives. Do not add long runs, stress, a comprehensive native matrix, real 300-second timeout, or source scan tests.

After Luna implementation and a new clean candidate, the Coordinator may prepare independently pinned, new L1 authority and fresh output, then separately authorize exactly one fixed batch. This ADR itself does not launch and does not reuse DE398 preparation or any execution authority absent from d95.

Any future real SourceProof admission jointly rechecks: (1) a valid L1 result and journal chain for the same current candidate and fixed runtime/code boundary; (2) required L0 lifecycle/timing/schema evidence; (3) existing census admission for the current candidate; and (4) independent fresh SourceProof authority V3 and execution authority V1, complete current pins, and one-shot execution authorization.

L1 closes only native-entry/cleanup admission; it proves neither source content nor that work fits within 270 seconds. Changes to native boundary, entry/admission, related policy, or runtime require revalidation of affected fixed items; old-candidate evidence is not inherited. Ordinary implementation issues are batched by the Coordinator without another architecture decision or new test domain.

### 10. Current conclusion

The role/permission gap has a complete executable contract; real L1 remains `NOT VERIFIED`. No current probe or SourceProof launch is authorized. The 153 missing entries, Git/source-graph closure, and actual completion within 270 seconds remain `UNKNOWN`. D32 stays `NOT FROZEN`, Gate `NONE`; no formal SC/Gate change and no D33.

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

## ADR-D32-NON-SOURCE-L1-RUNTIME-AND-OUTER-CALLER-V1 — Full runtime-origin admission and bounded outer caller

**Status:** APPROVED WITH CONDITIONS — implementation contract only

**Decision authority:** GPT-6.1 Sol Max

**Decision date:** 2026-10-07

**Related milestone:** D32

**Related implementation baseline:** `fd9f7f10be303dc0d08456ab1a807db882d2b8e2` (clean Integration candidate)

This decision prospectively tightens only the exact `NON_SOURCE_L1` implementation. It closes the missing runtime-origin and outer-caller evidence contracts; it does not authorize a native attempt, import, SourceProof, census, proof, formal gate, D32 closure, or D33 work.

### 1. Exact migration scope

The sole L1 authority/result versions are `D32_BOUNDED_SOURCEPROOF_NON_SOURCE_L1_AUTHORITY_V2` / schema 2 and `D32_BOUNDED_SOURCEPROOF_NON_SOURCE_L1_V2` / schema 2, under policy `D32_SOURCEPROOF_NON_SOURCE_L1_V2`. Gate authority remains `NONE`; all existing three cases, at-most-two reader attempts, 60-second batch, 5/10/15-second case limits, output bounds, zero-create refusal and no-source-closure claims remain unchanged. V1, mixed, unknown, missing, extra, duplicate, wrong-type and cross-candidate/run/batch/process records reject. SourceProof authority/result V1 and all other schemas remain unchanged.

The L1 authority retains its existing candidate/repository/identity/six-code/runtime/invocation/case/limit bindings and adds one independently supplied `runtime_authority` file reference and a fixed `outer_caller` policy. The latter binds the existing trusted observer host and process role, the one fixed controller entry/invocation, bounded stdout/stderr captures, and retained ownership policy. The existing output object retains its original fields and adds exactly eight batch-derived root paths: controller, normal-reader and forced-reader runtime admissions; outer prelaunch, caller outcome and caller journal; and bounded controller stdout/stderr captures. No caller-chosen paths, arbitrary argv, environment dictionary, process image, observer, executable, helper or script are admitted.

The L1 result retains its V1 result facts and adds the pinned runtime-authority reference, the persisted outer-prelaunch reference, and exactly three fixed ordered runtime-admission slots: controller, normal reader and forced reader. A process/admission not run is represented explicitly as `NOT_RUN` with null process identity; no predicted PID, admission, launch, capture or cleanup fact may be supplied. Consumers bind every reference to the same candidate, authority, run, batch and actual process.

### 2. Runtime-content authority and per-process admission

The separately pinned runtime content candidate is `D32_NON_SOURCE_L1_RUNTIME_CONTENT_AUTHORITY_V1`, schema 1, with exactly these fields: `schema_version`, `record_type`, `purpose`, `gate_authority`, `status`, `candidate_sha`, `source_repo`, `repository_identity`, `powershell_runtime`, `distribution`, `resolver_policy`, `module_policy`, `startup_inputs`, and `limits`. It is a content candidate, not authority until its exact external path/SHA is independently pinned. The distribution reuses complete PowerShell module-content V2 file/directory/content/opened-identity/owner/security-descriptor/protected-ancestor/inventory-digest semantics. The resolver reuses the existing V2 Windows/Defender/ProgramData/volume-root policy without adding trusted writers or paths. No cache, PATH, CWD, user-profile, manifest, source, Cargo, application, or real-user configuration input is authority.

The runtime record binds actual `deps.json`, runtime configuration and protected startup configuration content or a protected verified-absence record, the trusted-platform-assembly and native search inputs, startup-hook absence, profiling state, and the fixed module policy. Unknown or external managed/native roots, assemblies, hooks, profile indirection, inherited search path, user CWD or PATH are refused before use. Limits are fixed at 4 MiB authority bytes, 4096 files, 1024 directories, 2 GiB aggregate inventory bytes, 256 MiB maximum single file, and 1024 resolver-list entries. Existing 16 MiB owned-buffer and 64 KiB result/journal caps remain unchanged.

Every process admission is `D32_NON_SOURCE_L1_RUNTIME_ADMISSION_V1`, schema 1, with exactly these fields: `schema_version`, `record_type`, `purpose`, `gate_authority`, `candidate_sha`, `batch_id`, `run_id`, `authority_reference`, `runtime_authority_reference`, `outer_prelaunch_reference`, `parent_admission_reference`, `powershell_host`, `runner_process`, `startup`, `entry_script`, `environment`, `clock`, `namespace_witness`, `module_import_order`, `module_closure`, `resolver_admission`, `import_verification`, `import_attempts`, `status`, `primary_error`, and `secondary_errors`. The typed records use the current PowerShell module-content V2 runtime, resolver and origin records, including actual PID/creation/image/ordinary-token identity, fixed File operand and argv, actual 15-variable UTF-16 environment block digest, autoload/module-path/startup/resolver inputs, and all actual managed/native origins. Unknown, incomplete, copied, stale or cross-process admissions reject. A child witness is caller-owned and cannot be synthesized by the child. Post-startup observations cannot claim that they prevented startup.

The fixed Utility policy is `NON_SOURCE_L1_UTILITY_ONLY_V1`: the controller may load only the fixed, pinned PowerShell Utility manifest closure, exactly once after caller prelaunch and module-free startup/input validation; its admitted cmdlets are only `Add-Type` over the existing inline native surface and `ConvertTo-Json`. Management/Cim imports are forbidden. Readers import zero installed modules and use only finite managed waits, not `Start-Sleep`. Replace `Join-Path` with managed/Core path composition. The controller has no authority to use Codex runtime/cache or application configuration. Startup/admission, initialization, launches, captures, cleanup, result/journal persistence and caller return all spend the one shared batch T0.

### 3. Fixed bounded outer caller

The outer-caller function is part of the existing six-file controller closure. It adds no seventh script, image, helper, shell, service, observer process or public arbitrary-launch parameter. Real production calls use only the independently pinned existing trusted observer and bind its actual host/process; the L0 test adapter is synthetic and refuses the real route.

Before the one controller `CreateProcess` attempt, the caller validates the authority/runtime/six code references and owner-bound root/parent identities and descriptors; captures one shared QPC T0; constructs the exact executable, finite raw Windows command line, CWD and cleared fixed 15-entry UTF-16 environment; proves no inherited ambient handles; and creates immutable prelaunch evidence containing actual caller PID/creation/image/token, controller entry and image references, argv/environment, creation flags, STARTUPINFOEX attributes, successful handle-list application and observed handle roles/access/inheritability, configured outer Job, and all live file/root fences. It flushes, closes and reopens the create-new prelaunch record to bind bytes, hash and file identity before `CreateProcess`. A missing or null prelaunch input yields zero creation.

#### 3.1 Non-circular outer-prelaunch binding amendment

`ExpectedOuterPrelaunchBindingSha256` is a binding digest, not the prelaunch file SHA. The prelaunch `arguments` object has exactly three fields: `vector` (the actual host argv excluding executable), `command_line` (the exact raw `CreateProcessW` string), and `command_line_utf16_sha256` (SHA-256 of UTF-16LE bytes with no BOM or terminating NUL). For the fixed controller argv, the parameter token is at zero-based vector index 16 and its value at index `k = 17`; that value is the only binding position, and its placeholder `Z` is exactly 64 ASCII zero characters.

Given complete record `D`, form projection `P(D)` by copying all facts, changing only `vector[k]` to `Z`, and rebuilding `command_line` and its UTF-16LE digest with the same candidate-pinned Win32 argument renderer used for the actual call. Compute `H = SHA256(ASCII("D32_NSL1_OUTER_PRELAUNCH_BINDING_V1\n") || C(P(D)))`. `C` is compact UTF-8 canonical JSON with recursively ordinal-sorted object keys, preserved array order, short decimal integers, JSON booleans/null, and strings encoded by the default `System.Text.Json.Utf8JsonWriter` encoder, without BOM or final newline. Reject duplicate or extra fields, non-integer numbers, invalid Unicode, NUL argv elements, duplicate/missing binding parameters, or any other noncanonical input before creation.

The fixed order is: collect actual facts with `Z`; calculate `H`; substitute `H` at the unique vector position and rebuild the raw command line and UTF-16LE digest without changing any other fact; create-new, flush, close, reopen, and independently pin the final `D` bytes/SHA/file identity; then pass that exact stored `D.command_line` to the native call without rewriting it. Creation, assignment, resume, capture, and cleanup facts are recorded only later. No placeholder record, fixed-point search, backfill, self-file-SHA field, duplicate argv-derived field, or stored extra copy of `H` is permitted. The controller and readers receive the same `ExpectedOuterPrelaunchBindingSha256`; all compare it to the independently verified caller binding. Full file SHA remains the ordinary record/journal pin and must never be substituted for `H`.

#### 3.2 Existing observer identity and startup-input boundary

The outer caller's `observer_host_reference` and `observer_process.image_reference` are the same exact V2 file reference for the actual existing trusted observer image. The process record binds that observer's positive PID, creation FILETIME, and ordinary-token flags. This image is distinct from the fixed Program Files PowerShell child image; neither observer reference aliases `powershell_runtime`. The outer caller directly revalidates the live observer process/image/token and a finite startup digest immediately before its sole controller creation attempt. The controller entry reference remains the exact fixed six-file controller pin.

The fixed outer entry is invoked in the existing observer using only `& $ExactPinnedController -Repository $ExactRepository -CandidateSha $ExactCandidate -L1AuthorityPath $IndependentPath -ExpectedL1AuthoritySha256 $IndependentSHA256 -FixedOuterCaller`. The observer may have its own established host startup form; it is not required to use the child `-File` operand, the child's 15-variable environment block, or the child's post-startup admission. The Program Files child controller and its readers retain their existing fixed `-File`, cleared 15-variable environment and complete per-process runtime admission. No observer, helper, image, arbitrary launch parameter, or process enumeration is added.

Observer-binding preparation is candidate-only: it may bind the current observer identity/token, its finite startup digest and the fixed entry, but cannot create an authority, output, Job or child or call the outer route. The coordinator independently reopens/pins the candidate and returns those pins through the existing control channel to that same live observer. The fixed caller reopens and revalidates its current observer facts before creation; if the existing control channel cannot return the pins to the same observer, processing stops without an alternate observer or retry. Observer `RuntimeContext`, loaded modules, AppContext values and loaded-origin sets are never copied into target-child TPA, native-search or loaded-origin evidence. Unknown target-runtime inputs remain explicit candidate gaps; they do not authorize probing the child.

Within `startup_inputs`, `trusted_platform_assemblies.paths` is a nonempty, case-insensitively sorted list of full V2 file references cross-bound to the PowerShell distribution or Windows OS component file records. `native_search.paths` is a nonempty, case-insensitively sorted list of full V2 directory records (kind, canonical path, opened identity, owner and complete security descriptor); it is not a list of file references and cross-binds only to fixed PowerShell or Windows OS distribution directories. Each list has the existing 1024-entry limit and its V2 inventory digest is recomputed by the strict consumer. A file-as-directory substitution, empty or unknown list, digest drift, or cross-reference mismatch rejects.

For a protected-absence startup role, the witness is `SHA256(UTF8(J))`, where `J` is compact JSON in this exact insertion order: `policy_id`, `role_path`, `parent_directory`. The policy ID is `D32_NON_SOURCE_L1_PROTECTED_ABSENCE_V1`; `role_path` is the canonical fixed role path; `parent_directory` contains exactly the V2 directory fields `kind`, `path`, `volume_serial_hex`, `file_id_hex`, `owner_sid`, `security_descriptor_sddl`, `security_descriptor_sha256`, in that order. The parent must be the exact directory record in the pinned distribution, and the role path must not also occur as a present V2 file. This witness binds a protected absence claim; it does not replace the independently pinned distribution or authorize a runtime probe.

The only inherited standard handles are a read-only NUL stdin and separate controller stdout/stderr pipe write ends. Parent read ends are non-inheritable and retained by the caller. The exact three-handle allowlist and actual `UpdateProcThreadAttribute` success are recorded. Any null, unknown, unexpected, inherited ambient handle, descriptor mismatch or missing live fence refuses before creation. Controller and reader argv/environment remain fixed and cross-bind to their admission file path/SHA. Controller-owned reader admissions bind the controller admission SHA/path.

The caller uses a retained non-breakaway, kill-on-close outer Job with active-process limit two, preserves existing nested-job compatibility and reader Job active-process limit one, and creates the controller suspended, verifies/assigns/resumes at most once, retains its process and Job handles, and independently checks native Job process accounting rather than trusting an API return. It terminates/cleans up only a retained process/job it owns; never by PID/name or global process enumeration. The caller captures stdout and stderr separately into create-new references, each capped at 16,000 bytes (empty is valid), and proves bounded EOF/join; overflow, missing EOF or unproven join cannot complete.

The caller outcome (at most 64 KiB) binds prelaunch, actual creation/assignment/resume/native identity/exit, Job accounting, capture joins and references, all three admissions, inner result/journal or their absence, errors and clock. A distinct at-most-64-KiB append-only caller journal is flushed after the outcome and records its bytes/hash/opened identity and submission. An independent observer reopens and verifies caller return; outcome cannot self-prove post-flush return. All caller work remains within the same 60-second window. Zero-create refusal is `REFUSED` / `NOT_REQUIRED`; verified owned-cleanup failure is `BLOCKED`; unknown ownership/witness/cleanup is `UNRESOLVED` and stops further creation. Missing inner facts are never backfilled. There is no automatic retry.

### 4. Validation and stop conditions

Implementation evidence is one aggregate pure L0 batch: actual production caller/controller/case/producer/strict JSON consumer/journal/reconciliation flow with an in-process synthetic adapter only. Cover V1/mixed/extra/missing/duplicate/wrong type/cross-reference and runtime origin/autoload/startup-hook/resolver failures, file-fence loss, null/prelaunch/backfill rejection, NUL and pipe roles, inherited handles, exact allowlist, nested Job accounting, capture overflow/EOF/join, late or missing records, unknown cleanup, reader imports zero, zero-create failure, and real-route adapter refusal. Reuse frozen case, budget, buffer and record limits; add no stress, extra cases, runtime scans, runtime imports, child process, P/Invoke process creation, Cargo, source proof, census, network, helper, cache or real configuration access in this implementation batch.

The historical `5a260` attempt remains `UNKNOWN`/`UNVERIFIED`; this ADR and L0 evidence do not establish its runtime origin, cleanup or result. Only after the implementation L0 batch closes may a separate recovery preparation bind the old run, a fresh native UInt64 uptime baseline from the existing host and the user's chosen OS restart, and create a new disposition. That disposition can retire only the review block for a future fresh L1 review; historical cleanup remains unknown, gate authority remains `NONE`, and launch authority remains false. No earlier 2b5f8 recovery disposition is reused.

This decision authorizes implementation and pure L0 validation only. It does not authorize an L1 launch, new attempt/authority, runtime import, runtime/census/source/cache scan, SourceProof, formal gate, PASS/FROZEN, D33, or reclassification of historical cleanup.

### 5. Dedicated existing-observer preparation session amendment (2026-10-08)

This approved implementation clarification adds one fixed preparation-only parameter set to the existing six-file controller closure. A dedicated direct PowerShell host session may be authorized separately after this implementation commit and independent source/code-pin review. This amendment does not authorize starting that session now, scanning runtime content, capturing a baseline, restarting the OS, or invoking the outer caller.

The fixed entry is the existing controller in the existing trusted observer process, invoked with only its pinned repository and current candidate plus the PreparationSession switch. It disables PowerShell module autoload for the session before preparation work proceeds. It adds no seventh script, image, helper, service, observer process, public command parser, arbitrary command/path input, or new installed import. The session binds actual current PID/creation FILETIME, one opened observer image, ordinary token, finite startup digest, and the exact six current code references. It does not predict a child identity or treat the observer as the Program Files child runtime. If the fixed host/entry cannot establish the existing observer facts using the already-approved in-process surface, it refuses; there is no alternate host, helper, retry, or PID/name termination.

The control channel is strict JSON Lines with protocol D32_PREP_OBSERVER_CONTROL_V1. Every inbound frame has exactly protocol, session_nonce, sequence, candidate_sha, operation, and payload. The session nonce is a fresh lowercase 32-hex value, the candidate is the current exact SHA, and sequence is a strictly increasing positive Int64. Operations are the fixed enum READY, PREPARE_RUNTIME_CANDIDATE, VERIFY_RETURNED_PINS, CAPTURE_OLD_RUN_UPTIME_BASELINE, and CLOSE, each with its exact fixed payload shape and ordering. Duplicate JSON properties, malformed or extra fields, wrong types, wrong nonce/candidate, replayed or out-of-order operation, and identity/code-pin drift fail closed. Input is data only and is never passed to a PowerShell parser, Invoke-Expression, ScriptBlock.Create, or an argument/command interpreter. Every reply fixes gate and launch authority to NONE.

READY, PREPARE_RUNTIME_CANDIDATE, CAPTURE_OLD_RUN_UPTIME_BASELINE, and CLOSE require an empty object payload. VERIFY_RETURNED_PINS requires exactly identity, source_pins (the six ordered current code references), and runtime_candidate_reference; the identity has exactly process_id, creation_filetime_ticks, image_reference, ordinary_token, observer_startup_sha256, and entry_reference. The opening challenge uses sequence zero and operation CHALLENGE; every later response has exactly protocol, session_nonce, sequence, candidate_sha, operation, status, gate_authority, launch_authority, and payload. Successful operation responses echo their accepted operation sequence; a refusal response is terminal, and replies contain no non-JSON stdout. No operation writes a non-candidate authority or launches a process.

The immutable session lease is 1,800 seconds from start; actual observer-identity validation is bounded to 15 seconds, the one runtime-content preparation to 300 seconds, and each control-input wait to 300 seconds. A timeout, late completion, EOF, protocol or identity error, explicit CLOSE, or lease expiry closes the owned streams and retained file/directory fences and exits the owned host session. No automatic restart or cleanup assertion follows from this exit. Only the retained tool session may confirm its own exit; the implementation never kills by PID or process name.

PREPARE_RUNTIME_CANDIDATE runs at most once and uses only the existing finite Program Files PowerShell distribution, Windows/Defender/Utility and startup/resolver V2 evidence path, fixed dependency/runtime configuration and protected configuration content or verified absence. Existing inventory and resolver limits remain unchanged. The single create-new output is an untrusted runtime-content candidate under the fixed E:\d32\D32-NON-SOURCE-L1-RUNTIME-CANDIDATE-{candidate-prefix}-{session-nonce}.json naming rule; it is neither self-pinned authority nor proof. It does not import modules, inspect the Codex runtime/cache, profile or user/application configuration, query child runtime origins, launch a child, or create an L1 authority/root/attempt. If the finite proof cannot be completed through the already-approved in-process OS API surface without a new installed import or broader probe, it returns explicit gaps and stops.

Only after that candidate has been independently reopened and pinned may the same live observer receive those pins through its existing control channel and execute VERIFY_RETURNED_PINS once. It revalidates its actual identity, startup digest, candidate and six code references before any later preparation. CAPTURE_OLD_RUN_UPTIME_BASELINE is separately ordered after successful candidate and pin verification and is at most once. It binds the exact historical 5a260368a65644f28195842860c86dc1 caller record (18,157 bytes; SHA-256 398a7c57055bc0a2c9e7f4af4a695451587f6a20c12579c5494c379952a82e04), current actual observer and code pins, UTC and QPC ordering, and the actual UInt64 result of the existing GetTickCount64 export. The export target must be an OS System32 MEM_IMAGE with the independently verified Microsoft image/source relationship. UTC is not used to calculate uptime, signed or truncated tick values reject, and boot-GUID or 32-bit wrap criteria are not introduced. The fresh baseline is create-new at E:\d32\D32-NSL1-RECOVERY-BOOT-BASELINE-V1-5a260368a65644f28195842860c86dc1-{session-nonce}.json, is not reusable from the earlier 2b5 recovery, and does not request or perform a restart or create a post-restart disposition.

The typed baseline candidate is D32_NON_SOURCE_L1_RECOVERY_BOOT_BASELINE_V1 schema 1 with exactly schema_version, record_type, purpose, gate_authority, launch_authority, status, candidate_sha, old_run_id, session_nonce, source_repo, observer, source_pins, runtime_candidate_reference, old_caller_reference, old_locked_references, native_uptime, monotonic_capture, and control_order. The observer binds the actual ordinary-token identity and startup digest to the exact fixed entry and six ordered code pins; the image must not alias the Program Files child runtime. The old locked reference set includes the exact historical caller record. The native value is parsed and serialized as JSON UInt64, and the kernel32 export image is pinned as System32 kernel32.dll while the actual export target is separately pinned as a Microsoft-verified System32 MEM_IMAGE. The monotonic capture binds a positive QPC frequency and ordered signed-QPC samples alongside parseable UTC values with UTC offset and nondecreasing order. This typed record remains recovery candidate evidence, not a disposition or cleanup proof.

This amendment adds no schema version or semantic change to the frozen L1 authority/result, runtime-content candidate, runtime admission, or SourceProof schemas. Runtime-candidate output remains untrusted until independent external pinning; baseline preparation remains recovery evidence only. A failed runtime-candidate preparation skips baseline capture. Completion of preparation cannot retire historical cleanup UNKNOWN, satisfy a real L1 attempt, establish Gate/PASS/Phase 0, or authorize D33.
