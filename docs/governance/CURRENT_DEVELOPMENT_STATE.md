# CURRENT_DEVELOPMENT_STATE.md

> 本文件是 Codex 每轮进入项目时读取的短状态页。它是缓存，不覆盖 Git、已批准决定或 exact-SHA evidence。

## 1. 当前阶段

- **Milestone / Task:** D32 final-gate readiness（D32-A-R2）
- **Status:** NOT FROZEN
- **Current Stage Contract:** docs/governance/SC-D32-V1.md
- **Stage decision:** ADR-D32-GOVERNANCE-V12-RECONCILIATION，Sol Max 批准并自 2026-09-27 前瞻生效。

SC-D32-V1 的建立日期不声称存在先前 ratification；它以列明的 e902 baseline 开始约束后续 D32 gate work。

## 2. Git 参考

**Base / merge-base:** 4c727ec5ba42e0288400d5847b43b08a1c96bc54

**Integration parent / D32 baseline before this repair batch:** e902a05bf3193212c131c78ec7dfe6b72e2c292f

本治理与 raw-stream repair batch 之后的 gate candidate SHA 必须在执行门禁时从 Git 读取。Gate 前记录当前 branch、HEAD、parent、merge-base（适用时）和 clean Integration Tree；本状态页不预填它自己的 commit SHA。

## 3. 本批次范围和状态

- Earlier governance/raw-stream repair synchronized protocol v1.2 and SC-D32-V1, then repaired fixture child stdout/stderr raw capture. Its evidence remains bound to its old exact SHA.
- The current prospective repair batch implements ADR-D32-PHASE0-COMPACT-EVIDENCE-V1 plus the approved exact locked vendored-protoc authority: exclusive fresh external EvidenceRoot, identity-bound owner marker, fixed `r\c`/`r\t` storage, a Coordinator-pinned external authority and fresh per-run grant, fixture provenance V4, Phase0 V4, release attestation V5, aggregate V4, and failure-only blocked-diagnostic V1. Profile V2, debug/Job trace V2, fixture manifest v3, and D31 recovery-seeder provenance V2 remain unchanged. The separate D31 seeder grant/companion attestation is approved in principle but remains an explicit deferred implementation batch; Phase0/Phase1 authority is not reusable for it.
- Path-budget correction: 286 characters is the failing `.snap` path's **full** length, not a suffix length. The old Cargo-home prefix is 74 characters, leaving a 212-character suffix; replacing that prefix with compact `E:\p0r3\r\c` (11 characters) yields 223 characters. The Coordinator's read-only pinned-tree census reported 6,800 files / 878 directories and a longest projected compact path of 230 characters, 17 below the 247-character successful directory-path probe. This arithmetic/census is not Phase 0 evidence; the proposed `E:\p0r3` root is currently absent and still needs exclusive, canonical, non-reparse creation and opened-handle identity verification at run time.
- Old-SHA quarantine ledger/leaves are preserved and remain locked; they are not rebound as evidence for this candidate. Before any new Phase 0 run, prove all five fixture source paths absent and produce fresh outputs. No Phase 0, Cargo, network, release, move, canary, or gate has been run for this repair batch.
- The exact candidate remains NOT FROZEN. New Phase 0 and downstream evidence must be regenerated for the committed exact SHA; prior SHA evidence and PASS never transfer.
- 当前没有因此关闭任何 D32 final gate，候选状态仍为 NOT FROZEN。

## 4. 尚未关闭的门禁

- [ ] Phase 0：五个 fixture phases、完整 protocol/Vita/Host 本地 suites、ADR 指定的 named checks 与 process/cleanup evidence
- [ ] Phase 1：两条固定 locked release Cargo commands、fresh 三件 flat artifacts、bundle manifest 和 sibling attestation
- [ ] 完整 post-bundle aggregate，bundle hashes = VERIFIED
- [ ] 十个 D31 real-process cases（Phase 0 期间明确 NOT RUN）
- [ ] Post-aggregate D31 recovery-seeder use is blocked until its separate fresh run/home owner marker, per-run grant, and D32-only companion helper-auth/trace attestation are implemented and validated; the Phase0/Phase1 grant is never reusable.
- [ ] 适用且用户已授权 provider 时运行四个 D29G2 real-provider cases；未授权时不得把 NOT RUN 记为 PASS
- [ ] 八个按 SC-D32-V1 固定顺序运行的 real Host modes 与全部适用 negative evidence
- [ ] 对同一 exact candidate 完成 Codex Red Team review 和 Luna High whole-candidate gate
- [ ] Luna High PASS 后提交 exact-SHA packet，由 Sol Max 完成 D32 closure
- [x] 三个 interactive/physical capture cases：N/A — NOT RUN；依现有 D32 决定记录理由，不计为 PASS

## 5. 冻结状态

**D32 candidate status:** NOT FROZEN

Phase 0、Phase 1、full aggregate、D31 real-process、适用 D29G2 provider、八个有序 Host modes、Red Team、Luna High 和 Sol Max D32 closure 均未在本状态页建立当前 exact-candidate evidence。证据缺失不代表 PASS。

## 6. 后续 gate 顺序

1. 读取实际 Git 状态，记录当前 clean Integration Candidate exact SHA 和适用 profile/toolchain inputs。
2. 按 ADR-D32-PHASE0-TOOLCHAIN-PROFILE 完成 Phase 0 五个 fixture phases、full local suites 和 named checks。Phase 0 不运行 release build、D31 real-process/seeder、provider request、physical capture 或 Host real canary。
3. Phase 0 通过后，只运行 ADR-D32-EVIDENCE-BUNDLE-V1 指定的两条 fixed locked release Cargo argv，生成 fresh 三件 flat artifacts、manifest 和 sibling attestation。
4. 立即验证 schema、SHA、commands、hashes/bytes/file identities、flat layout、runtime_resources = []、Tauri resource map 与 clean state；随后完成 full §16.1.5 aggregate，bundle hashes = VERIFIED。
5. Aggregate 通过后，先完成独立 D31 recovery-seeder grant/companion-attestation 批次并由 Coordinator/Luna High 验证，方可运行依赖该 seeder 的 D31 real-process case；它必须使用 fresh seeder run/home、create-new owner marker 和独立 per-run grant，绝不复用 Phase0/Phase1 grant。随后完成十个 D31 real-process cases，以及适用且用户已授权的四个 D29G2 provider cases。三个 interactive/physical capture cases 继续标为 N/A — NOT RUN。
6. 在同一 exact candidate 上按 SC-D32-V1 的精确顺序运行八个 Host real-canary modes，并建立 required negative evidence。
7. 对同一个 clean exact candidate 完成 Codex Red Team 和 Luna High gate。Repair 后新 SHA 必须重建受影响 evidence 并重新 gate。
8. Luna High PASS 后交 Sol Max 做 D32 closure。任务在 D32 结束；不做 D33 规划或 Stage Contract。

任何 repair 都会产生新 candidate SHA；受影响 evidence 和后续 gate 必须针对新 SHA 重建。
