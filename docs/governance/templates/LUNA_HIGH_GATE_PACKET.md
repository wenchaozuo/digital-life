# LUNA HIGH GATE PACKET

Gate model: Luna High / GPT-6

Stage / Task:
Stage Contract:
Frozen invariants:

Integration branch:
Base:
Parent:
Candidate:
Integration working tree:

Governance revision / applicable D32 ADR supersessions:
Reviewer independence (no candidate implementation):
Required evidence checklist with exact candidate/reference hashes:

## Worktree integration status
All Patch Worktrees integrated/cleared: YES/NO
Outstanding unintegrated patches:
- ...

## Diff scope
- ...

## Focused tests
- ...

## Broader/full tests
- ...

## Real canary
- ...

## Negative evidence
- ...

## Known limitations
- ...

## Gate instruction

Review only the final Integration Candidate exact SHA.

Do not treat Patch Worktree branch/commit evidence as a substitute for integrated candidate evidence.

Perform a whole-candidate independent review.

Do not stop at the first ordinary blocker if further safe review can find additional blockers.
Return the complete blocker set you can establish in this pass.

Return exactly one top-level verdict:

### PASS

### BLOCKED_IMPLEMENTATION
Use when closure is possible without changing frozen architecture / Stage Contract.

### BLOCKED_ARCHITECTURE
Use only when closure requires architecture/invariant/Stage Contract change.

For each blocker:
- Requirement
- Evidence
- Failure
- Required closure proof
- Root-cause/dependency cluster and safely unreviewed scope

Do not repeat every expensive command by default. Independently inspect evidence and run necessary authorized checks; record omissions. Required real/negative evidence cannot be replaced by focused/static tests. Old candidate PASS does not transfer.

Return to Coordinator. Do not contact Sol Max directly.
