# SC-D32-V1 — D32 Final-Gate Completion

**Status:** ACTIVE
**Decision authority:** GPT-6 Sol Max
**Decision date:** 2026-09-27
**Effective:** 2026-09-27, prospective
**Baseline:** e902a05bf3193212c131c78ec7dfe6b72e2c292f
**Related milestone:** D32 final-gate readiness (D32-A-R2)
**Related decision:** ADR-D32-GOVERNANCE-V12-RECONCILIATION

## Authority and scope

Sol Max establishes this Contract prospectively effective 2026-09-27, using the listed e902 commit as the D32 Integration starting baseline. The date does not claim a prior ratification, and the baseline is not evidence that any gate passed.

AGENTS.md and CODEX_DEVELOPMENT_PROTOCOL.md v1.2 govern the Coordinator, Worker, workspace, Integration/Build Owner, Git and gate workflow. The candidate's complete D32 protocol supplement §§16.1.1–16.1.5 remains in force, including its sole, exact Phase 0 → Phase 1 exception. Existing D32 ADRs and FROZEN_INVARIANTS.md remain unchanged.

This Contract covers D32 final-gate completion only. Work stops after Sol Max records D32 closure; this Contract does not plan or establish D33.

## Required sequence

1. **Bind the candidate.** Before each gate, record the Integration Tree branch/state, exact candidate SHA, base/parent/merge-base where applicable, and clean working tree. All evidence and both independent reviews must bind the same final exact SHA. Any repair produces a new candidate and requires rebuilding affected evidence.

2. **Complete Phase 0.** Run the fixed scripts/d32-phase0-matrix.ps1 runner under the caller-pinned toolchain and approved process-trace contract. Complete all five fixture build phases, the full protocol, Vita and Host local suites, and every exact named focused check in ADR-D32-PHASE0-TOOLCHAIN-PROFILE, Decision 2. Preserve its exact inventory, argv, process identities, ordered stdout/stderr captures and cleanup evidence. Use the approved default Cargo test parallelism.

   Phase 0 is local fixture/test preparation only. Mark all ten D31 real-process cases as NOT RUN — deferred until validated bundle and full aggregate. Mark the four D29G2 provider tests as NOT RUN — user-authorized provider required until their applicable user-authorized provider run is available. Mark the three interactive/physical capture tests N/A — NOT RUN with the reason required by the existing ADR. None is PASS. Record bundle hashes as PENDING; Phase 0 does not pass the §16.1.5 aggregate.

3. **Complete Phase 1.** Only after Phase 0 has passed, run exactly the two fixed locked release Cargo argv authorized by ADR-D32-EVIDENCE-BUNDLE-V1. Use a fresh external output location and fresh outputs for exactly three flat artifacts: vita-agent.exe, d32a-production-canary-host.exe and digital_life_lib.dll; include BUNDLE-MANIFEST.json in the bundle directory and D32-RELEASE-ATTESTATION.json as its sibling. Bind the exact candidate, commands, process/tool identities, file identities, bytes and hashes. Do not reuse prior or stale target outputs as evidence.

   Use the populated external CARGO_HOME bound by the Phase 0 record, the caller-pinned direct Cargo/Rust toolchain, the verified native tool profile and the explicitly constructed environment. CARGO_NET_OFFLINE=true is an environment input and does not alter either fixed argv. Do not invoke any additional build command.

4. **Verify the full aggregate.** Immediately validate schema, candidate binding, fixed commands and paths, all artifact hashes/bytes/identities, flat-only bundle layout, runtime_resources = [], Tauri shipping resource map and clean candidate state. Then establish the complete post-bundle §16.1.5 aggregate with bundle hashes = VERIFIED. No downstream expensive gate or real canary starts before this aggregate passes.

5. **Run deferred real evidence after aggregate.** Run all ten D31 real-process cases listed in ADR-D32-PHASE0-TOOLCHAIN-PROFILE, Decision 3. Run the four D29G2 real-provider tests — d29g2_real_provider_smoke, d29g2_r1_minimal_provider_probe, d29g2_r2_structural_diagnostic and d29g2_r2_role_matrix — only when applicable and the provider use is user-authorized. Do not count an unavailable or unauthorized provider run as PASS. Keep all three interactive/physical capture tests N/A — NOT RUN as established above.

6. **Complete the ordered Host canary and negative evidence.** On the same exact candidate, run all eight canonical modes in this exact order: positive; grant-replay; revoke-before-revalidation; life-before-revalidation; cancel-before-revalidation; migration-before-revalidation; executable-identity-tamper; environment-profile-tamper. Establish each mode's required denial, no-forbidden-mutation, identity, authority, process/handle/thread cleanup and other applicable negative evidence. Do not substitute compile, mock or fixture results for these real Host modes.

7. **Complete independent review.** Finish the Codex Red Team review and Luna High whole-candidate gate against the same clean Integration Candidate exact SHA. The required Luna High outcome is PASS; any repair creates a new candidate and invalidates affected old evidence.

8. **Close D32.** After every required item above and Luna High PASS, submit the exact-SHA D32 closure packet to Sol Max. Only Sol Max may record D32 architecture closure. Stop at D32; no D33 planning or contract follows.

## Exit criteria

- Phase 0, Phase 1, the full post-bundle aggregate, all applicable deferred real evidence, all eight ordered Host modes, required negative evidence, Red Team and Luna High PASS are established for one exact clean Integration Candidate.
- The three interactive/physical capture tests remain explicitly N/A — NOT RUN, not PASS.
- No unresolved architecture blocker remains; temporary Patch Worktrees, if any, have been integrated or cleaned up under v1.2 policy.
- Sol Max records D32 closure for the exact candidate SHA.

Missing evidence means BLOCKED. This Contract does not confer a gate PASS, candidate freeze or FROZEN status by itself.

## Approved Phase0 fixture-build budget addendum

Under the prospective, narrowly scoped ADR-D32-PHASE0-FIXTURE-BUDGET-V1, the five fixed owner-bound Phase0 fixture builds may use exactly `--jobs 4` and an explicitly caller-pinned 28,800-second per-build limit (`-Phase0FixtureBuildTimeoutSeconds 28800`). Formal Phase0 must still explicitly pin `-Phase0TimeoutSeconds 14400` for the three locked fetches, tool/list/test/focused commands, and H7 authority suite. The Phase0 default remains 1,800 seconds; standalone/default fixture work remains 600 seconds/jobs=1 and cannot attest a Phase0 budget.

Before Cargo starts, the runner must record and enforce at least 8 logical CPUs, 12 GiB available physical memory, 200 GiB free on the evidence volume, and zero competing target writers. Since Windows process census does not supply a reliable working directory, any active Cargo/rustc/cl/link/build-script process is conservatively treated as a possible target writer and blocks. It must retain the fresh empty owner-bound CargoHome and TempRoot, fixed lock/toolchain/argv other than the authorized five-build jobs token, normal target directories, V2 trace/Job accounting and cleanup, all five fixtures, all complete local suites and negative evidence, and only the existing five output-quarantine paths. No cache copy, target override, release/D31 timeout change, or ordinary test-concurrency change is permitted.

The strict schema sequence is fixture provenance V6, Phase0 V6, release attestation V7, and aggregate V6; old and unknown versions or any budget/argv drift are BLOCKED. Fixture manifest v3 and its six original environment fields, Profile V2, Trace V2, D31 seeder provenance V2, and every SC-D32-V1 gate requirement remain unchanged. This addendum changes no exit criterion and does not authorize a formal run by itself.
