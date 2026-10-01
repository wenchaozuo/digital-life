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

**Current inventory-authority batch base:** 756acd388620f7511034e7f3e8886fefb9ff6ea3

**Earlier D32 integration baseline (before the compact-evidence repair batch):** e902a05bf3193212c131c78ec7dfe6b72e2c292f

本治理与 raw-stream repair batch 之后的 gate candidate SHA 必须在执行门禁时从 Git 读取。Gate 前记录当前 branch、HEAD、parent、merge-base（适用时）和 clean Integration Tree；本状态页不预填它自己的 commit SHA。

## 3. 本批次范围和状态

- Earlier governance/raw-stream repair synchronized protocol v1.2 and SC-D32-V1, then repaired fixture child stdout/stderr raw capture. Its evidence remains bound to its old exact SHA.
- The current prospective repair batch implements ADR-D32-PHASE0-COMPACT-EVIDENCE-V1, the bounded fixture-build budget, ADR-D32-PHASE0-TEST-INVENTORY-AUTHORITY-V1, and the V2 supersession ADR-D32-POWERSHELL-MODULE-CONTENT-AUTHORITY-V2, alongside the approved exact locked vendored-protoc, tauri-macros source-patch, and H7-C direct-Git exceptions. PowerShell real-module admission requires an independently Coordinator-pinned schema-2 authority for the complete protected PSHOME distribution and resolver domain before fixed Management → Utility → CimCmdlets imports; no-pin validation is module-free and imports zero modules. The prior `1a180...` module-free admission remains BLOCKED before imports because its resolver-policy comparer incorrectly equated the caller-pinned static Windows finite inventory with that process's loaded native/managed set. Read-only validation reopened all 61 caller-pinned Windows refs, including unloaded `apphelp.dll`, with matching bytes/content/file identities/ACL and three directory fences; this is diagnostic evidence only. The current prospective implementation reopens the complete caller-pinned static component and keeps actual resolver origins as a separate exact subset check; 12/12 focused module-free cases pass with zero imports/children/Cargo and no installed writes, including an absent-path read-only refusal probe. No fresh exact-SHA authority pin, real module admission, D32 PASS, or gate is established. The specifically authorized RTSS process and loader were exited normally/precisely in the earlier scoped run; this repair did not census or alter RTSS or its configuration. The tauri-macros 2.6.3 patch remains source/archive/lock-bound; only the exact direct pinned Git.exe child of the accepted Vita libtest may be continued under a Coordinator-pinned external suite authority and fresh owner/run/root/temp-bound grant. Current strict schemas are fixture provenance V7, inventory discovery V2, inventory baseline V2, Phase0 matrix V8, release attestation V9, and aggregate V8; blocked-diagnostic V1 remains failure-only. Profile V2, debug/Job Trace V2, fixture manifest v3, and D31 recovery-seeder provenance V2 remain unchanged. The separate D31 seeder grant/companion attestation remains deferred; Phase0/Phase1 authority is not reusable for it.
- The latest authorized formal Phase0 attempt before the present prospective budget migration was the one-shot `E:\p0r12` attempt on candidate `06c300d94792e2a9aed4c47cb1db7b1a69551861`; it was BLOCKED at the first fixture after the fixed 14,400-second command limit. Its evidence remains immutable and bound to that attempt. ADR-D32-PHASE0-FIXTURE-BUDGET-V1 now prospectively authorizes exactly the five owner-bound fixture builds to use `--jobs 4` and 28,800 seconds each, after strict capacity preflight; all fetch/test/non-build commands remain 14,400 seconds. This implementation batch itself runs no Cargo or formal Phase0 and does not rebind earlier evidence.
- Historical path-budget correction (the `E:\p0r3` proposal has since been consumed and is not a current root): 286 characters is the failing `.snap` path's **full** length, not a suffix length. The old Cargo-home prefix is 74 characters, leaving a 212-character suffix; replacing that prefix with compact `E:\p0r3\r\c` (11 characters) yields 223 characters. The Coordinator's read-only pinned-tree census reported 6,800 files / 878 directories and a longest projected compact path of 230 characters, 17 below the 247-character successful directory-path probe. This arithmetic/census is not Phase 0 evidence.
- Old-SHA quarantine ledger/leaves and prior `E:\p0r3`–`E:\p0r12` evidence remain immutable and bound only to their original attempts; none is rebound by this batch. Any future Phase 0 must use a separately authorized fresh root and prove all five fixture source paths absent before creation. No Phase 0, Cargo, network, release, move, canary, or gate has been run for this bounded-budget implementation batch.
- The exact candidate remains NOT FROZEN. New Phase 0 and downstream evidence must be regenerated for the committed exact SHA; prior SHA evidence and PASS never transfer.
- Before any next formal Phase0, the Coordinator must obtain independent fresh pins for the exact clean candidate's module-free Profile V2 and `D32_POWERSHELL_MODULE_CONTENT_AUTHORITY_V2` candidates; the static Windows pin repair and focused synthetic tests do not substitute for either pin or for a fresh real admission. The installed runtime must satisfy the full Windows/Defender identity, namespace, static-reference, and live-origin checks; no prior RTSS observation is reused as current evidence. No system/security-software configuration is changed by this batch. Only after module admission is independently available may the Coordinator prepare and pin new protoc/source/Git/test-inventory inputs for that SHA. Run separate monitored six-command list-only discovery in a fresh root/home/temp, independently review it, and pin `D32_TEST_INVENTORY_BASELINE_V2`; formal Phase0 must re-run and match those list sets before suite execution. All external inputs and evidence from 28c5792 or earlier remain immutable and cannot be rebound after the new commit. This implementation batch runs no Cargo, fetch, discovery, formal Phase0, root claim, release, canary or gate.
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
2. 先按 ADR-D32-PHASE0-TEST-INVENTORY-AUTHORITY-V1 对该 exact candidate 运行单独六命令 list-only discovery，由 Coordinator 审查并 pin 外部 baseline path/SHA；再按 ADR-D32-PHASE0-TOOLCHAIN-PROFILE 完成 Phase 0 五个 fixture phases、formal list 比对、full local suites 和 named checks。Phase 0 不运行 release build、D31 real-process/seeder、provider request、physical capture 或 Host real canary。
3. Phase 0 通过后，只运行 ADR-D32-EVIDENCE-BUNDLE-V1 指定的两条 fixed locked release Cargo argv，生成 fresh 三件 flat artifacts、manifest 和 sibling attestation。
4. 立即验证 schema、SHA、commands、hashes/bytes/file identities、flat layout、runtime_resources = []、Tauri resource map 与 clean state；随后完成 full §16.1.5 aggregate，bundle hashes = VERIFIED。
5. Aggregate 通过后，先完成独立 D31 recovery-seeder grant/companion-attestation 批次并由 Coordinator/Luna High 验证，方可运行依赖该 seeder 的 D31 real-process case；它必须使用 fresh seeder run/home、create-new owner marker 和独立 per-run grant，绝不复用 Phase0/Phase1 grant。随后完成十个 D31 real-process cases，以及适用且用户已授权的四个 D29G2 provider cases。三个 interactive/physical capture cases 继续标为 N/A — NOT RUN。
6. 在同一 exact candidate 上按 SC-D32-V1 的精确顺序运行八个 Host real-canary modes，并建立 required negative evidence。
7. 对同一个 clean exact candidate 完成 Codex Red Team 和 Luna High gate。Repair 后新 SHA 必须重建受影响 evidence 并重新 gate。
8. Luna High PASS 后交 Sol Max 做 D32 closure。任务在 D32 结束；不做 D33 规划或 Stage Contract。

任何 repair 都会产生新 candidate SHA；受影响 evidence 和后续 gate 必须针对新 SHA 重建。
