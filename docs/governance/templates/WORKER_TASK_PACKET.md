# WORKER TASK PACKET

Prepared by: GPT-6.1 Sol Medium Coordinator
Worker: GPT-6 Luna Max

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
