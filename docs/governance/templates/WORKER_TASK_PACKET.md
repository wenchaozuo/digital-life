# WORKER TASK PACKET

Prepared by: Sol Medium Coordinator

Worker: Luna Max / GPT-6

Governance revision / fingerprints:
Integration path / observed SHA:
Task ID / write owner / dependencies:
Unique Build Owner (if relevant):
Expected duration / watchdog: default 90 minutes; reconcile with approved command deadlines

## Role
Scout / Implementer / Repair / Tester / Evidence / Red-Team / Integration-Build-Owner

## Execution mode
READ_ONLY / PATCH_WORKTREE / INTEGRATION / ISOLATED_BUILD_WORKTREE

## Goal
明确最终要解决的问题和期望产物。

## Current stage
Stage:
Stage Contract:
Base:

## Relevant context
- 只提供本任务必要的文件、symbol、现象和历史结论。
- 不默认复制完整项目历史。

## Frozen constraints
- MUST preserve ...
- MUST NOT change ...
- Historical forbidden paths / known traps:
  - ...

## Allowed modification scope
- Files/modules:
- Scope expansion rule:

## Required outputs
1. Findings
2. Changed files
3. Patch/local commit（如适用）
4. Tests that should be run
5. Negative evidence required
6. Assumptions / risks
7. Complete blocker set

## Census and validation scope
- Entries / producers / consumers / nested references:
- Parameter / serialization / path / identity / success / failure / cleanup coverage:
- Uncovered scope and reason:
- Impact map and L0/L1/L2 tests; required formal L3/L4 remain unchanged:
- Existing raw captures available for replay:
- Evidence authority: DEVELOPMENT_ONLY / FORMAL (only as authorized)

## Blocker policy
- MUST NOT contact Sol Max directly.
- Record blockers and continue safe, useful investigation.
- Return related blockers together to Coordinator.
- Stop dangerous mutation only when continuing may violate a frozen boundary or cause unsafe/irreversible effects.

## Build policy
- READ_ONLY: no writes.
- PATCH_WORKTREE: no normal build/test/canary.
- INTEGRATION: build/test only when assigned as Build Owner.
- MUST NOT `cargo clean` unless explicitly justified.
- No auto retry of expensive runs; record actual attempt ID/start count, exact inputs, last completed command, failing command and cleanup.
- D32 fresh CargoHome/fixed commands/required tests stay frozen; developmental labels grant no startup/helper/network authority.
- Use `EXECUTION_EFFICIENCY_POLICY.md` for batch repair, cache lifecycle and passive waiting; return the complete result, not periodic progress reports.

## Stop conditions
Stop and return to Coordinator if:
- closure requires changing frozen architecture/invariant/Stage Contract;
- schema/migration/authority/recovery/security/protocol semantics must change;
- assigned write scopes overlap unsafely;
- continued execution risks irreversible unsafe mutation.

## Autonomy
Choose the investigation and implementation approach yourself within the constraints above.

Prefer the smallest change that fully satisfies the requirement.

Do not invent new architecture when existing constraints are insufficient; report the architectural question instead.
