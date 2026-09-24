# CODEX_DEVELOPMENT_PROTOCOL.md

**Version:** 1.1  
**Status:** Project Governance Baseline  
**Scope:** 虚拟生命项目后续全部开发阶段。

## 0. 目的

让 Codex 长期自主执行工程工作，同时把不同推理强度用在最合适的位置：

- Sol Medium / GPT-6：Coordinator
- Luna Max / GPT-6：Worker
- Sol Max / GPT-6：Architect
- Luna High / GPT-6：Independent Gate

本协议重点避免：
- 子代理发现一个 blocker 就直接升级架构模型；
- blocker 一个一个 repair 导致重复编译；
- worktree 导致构建缓存分裂；
- Sol Max 被用于进度跟踪；
- Gate 只发现第一个 blocker 就退出；
- 状态文档过时导致回退开发阶段。

除非用户明确覆盖，本协议为强制规则。

---

# 1. 规范词

- **MUST / MUST NOT**：强制 / 禁止。
- **SHOULD / SHOULD NOT**：默认要求；偏离需有明确工程理由。
- **PASS**：当前 exact candidate 满足指定 gate。
- **BLOCKED_IMPLEMENTATION**：架构不变即可 repair 的问题。
- **BLOCKED_ARCHITECTURE**：需要 Architect 决策的问题。
- **Stage Contract**：由 Sol Max 确立的阶段目标、范围、禁止项和 exit criteria。
- **Exact Candidate**：当前门禁对应的精确 Git SHA。
- **Real Canary**：真实目标路径验证，不等价于 mock/compile/unit fixture。
- **Negative Evidence**：证明禁止行为没有发生的证据。

---

# 2. 控制层级

优先级：

1. 用户当前明确指令；
2. 已批准 Architecture Decision / Frozen Invariant / Stage Contract；
3. 本协议；
4. 已验证开发总文档；
5. Coordinator/Worker 工程判断。

低层级不得覆盖高层级。

---

# 3. Coordinator — Sol Medium

Coordinator 是日常长期总控。

MUST：
- 同步 Source of Truth；
- 识别 CURRENT_STAGE；
- 按 Stage Contract 拆任务；
- 调度 Luna Max worker；
- 控制并行写入；
- 汇总全部 blocker；
- 组织 batch repair；
- 组织集中 build/test；
- 生成 Luna Gate Packet；
- 在 Architect 触发条件满足时生成压缩 packet；
- 阶段 gate 通过后准备 closure/next-stage packet。

MUST NOT：
- 自行创造/改变 frozen architecture；
- 自行弱化 invariant；
- 自行修改 authority/schema/migration/recovery/security/protocol 的冻结语义；
- 频繁轮询 worker 或 Gate 进度；
- 用 Sol Max 做普通 blocker 分类。

Coordinator 可以在已冻结架构内做普通工程决策。

---

# 4. Worker — Luna Max

默认所有 Codex 工程 worker 使用 Luna Max。

Worker MAY 承担：
- Scout；
- implementation；
- repair；
- tests/fixtures；
- canary；
- evidence/root-cause analysis；
- read-only red-team。

Worker MUST：
- 只处理被分配范围；
- 遵守相关 invariant；
- 将 findings/blockers 汇总返回 Coordinator；
- 在安全范围内尽量完成本轮调查再返回。

Worker MUST NOT：
- 直接调用/汇报 Sol Max；
- 自行修改 Stage Contract；
- 自行修改 frozen invariant；
- 删除/弱化失败测试获得 PASS；
- 创建 git worktree；
- 无授权 push remote。

---

# 5. Blocker batching

发现 blocker 不等于立即 repair。

每轮 worker/reviewer：

1. 记录 blocker；
2. 标注 evidence；
3. 在继续操作安全且仍有价值时完成剩余调查；
4. 一次返回完整 blocker set。

Coordinator 收到多个结果后：

1. 去重；
2. 分析共同 root cause；
3. 分析依赖关系；
4. 分为：
   - implementation
   - evidence
   - architecture
5. implementation/evidence 尽量形成一个 repair batch；
6. 同一架构根因的 blockers 合并为一个 Architect Packet。

MUST NOT 以“一个 blocker → 一次 Sol Max → 一次 compile”的方式推进。

---

# 6. Architect — Sol Max

Sol Max 使用当前可用最高 Sol 推理等级，负责高信息密度架构任务。

只处理：

## A. Stage Contract
- 当前阶段没有有效 Contract；
- 上一阶段闭合后需要确立下一阶段；
- scope 已发生架构级变化。

## B. Architecture
- 新 authority / capability / trust model；
- grant/revoke 语义；
- persistence/schema/migration；
- identity continuity；
- crash recovery；
- concurrency invariant；
- filesystem security；
- source/toolchain authority；
- frozen external/IPC protocol。

## C. Architecture blocker
- blocker 批次的共同根因是冻结架构冲突；
- Luna High 返回 `BLOCKED_ARCHITECTURE`；
- 高可信证据证明现有 contract 本身不成立。

## D. Stage closure
阶段 gate PASS 后：
- 判断 architecture obligations 是否闭合；
- 明确哪些决定 frozen；
- 判断是否需要 repair stage；
- 确立下一 Stage Contract。

Sol Max MUST NOT：
- 跟踪 worker/Luna 进度；
- 逐个查看普通 blocker；
- 指挥常规 repair；
- 做普通 compile/test 分析；
- 重复 Luna High 的实现级 whole-candidate gate。

本协议**不规定 Sol Max 固定调用次数**。是否调用由职责和触发条件决定。

---

# 7. Independent Gate — Luna High

Luna High 与 Luna Max implementation context 必须逻辑隔离。

输入以 Gate Packet 为准，重点包括：
- Stage Contract / requirement；
- frozen invariants；
- base/parent/candidate；
- diff scope；
- focused/broader tests；
- real canary；
- negative evidence；
- known limitations。

Gate SHOULD whole-candidate review。

发现 blocker 后：
- 若继续审查安全且有价值，继续；
- 尽量一次性收集完整 blocker set；
- 不因第一个普通 blocker 自动退出。

输出：

### PASS
没有阻断当前 gate 的问题。

### BLOCKED_IMPLEMENTATION
问题可在不改变 frozen architecture/Stage Contract 的情况下修复。

### BLOCKED_ARCHITECTURE
关闭 blocker 必须改变/重新解释 architecture、invariant 或 Stage Contract。

Luna High MUST return to Coordinator，不直接联系 Sol Max。

---

# 8. Gate 后路由

## BLOCKED_IMPLEMENTATION
Coordinator：
- 汇总 blocker set；
- 由 Luna Max 批量 repair；
- 产生新 exact candidate；
- 重跑受影响 evidence；
- re-gate。

## BLOCKED_ARCHITECTURE
Coordinator：
- 完成本轮其余安全信息收集；
- 合并相关 architecture blockers；
- 生成一次 Sol Architect Packet；
- 等 Sol Max 新 decision/contract；
- 再执行实现。

## PASS
Coordinator：
- 生成 Stage Closure & Next Stage Packet；
- 交 Sol Max 做阶段架构闭合/下一阶段确立。

---

# 9. Workspace policy — no worktree

除非用户明确要求：

> MUST NOT create or use git worktrees.

原因：
- 保持单一真实 working tree；
- 复用 Cargo/incremental build cache；
- 避免重复依赖编译；
- 减少 merge 后重复 gate。

只读任务可以并行。  
写任务默认串行；若明确不重叠，可受控并行。

---

# 10. Build policy

Coordinator 指定 Build Owner。

推荐顺序：

`analysis -> repair batch -> write complete -> focused build/test -> broader suite -> real canary`

MUST NOT 让每个 worker 为每个小 blocker 独立清缓存/完整编译。

除非技术必要或用户明确要求：

> MUST NOT run `cargo clean` or equivalent cache reset.

失败测试可以先进行有针对性的低成本诊断，但最终 candidate 必须使用规定的统一验证。

---

# 11. Source of Truth

按 `PROJECT_SOURCE_OF_TRUTH.md` 自动发现和同步。

特别规则：

- Git actual state 决定代码现实；
- Frozen decisions/invariants 决定规范边界；
- Sol Max Stage Contract 决定正式阶段目标；
- latest verified development document 辅助恢复开发上下文；
- `CURRENT_DEVELOPMENT_STATE.md` 只是缓存。

不得只按文件名/修改时间猜“最新”。

---

# 12. Git discipline

Gate 前 MUST 记录：
- branch；
- base；
- parent；
- candidate；
- merge-base（适用时）；
- working tree。

规则：
- Gate 绑定 exact SHA；
- repair 后新 SHA 重新 gate；
- dirty tree 不可 final freeze；
- 默认本地 commit；
- 未经用户明确要求不 push remote；
- 禁止 worktree。

---

# 13. Real Canary

明确要求真实 Host/OS/filesystem/SQLite/process/toolchain/crash 行为时：

- mock PASS ≠ real canary；
- fixture PASS ≠ real canary；
- compile PASS ≠ real canary。

无法建立 required real canary：
`BLOCKED_IMPLEMENTATION`，除非根因是 architecture contract 本身不可实现，此时升级为 `BLOCKED_ARCHITECTURE`。

---

# 14. Negative Evidence

安全/权限/恢复阶段不能只证明 happy path。

按 Stage Contract 记录适用项，例如：

```text
unauthorized mutation = 0
mutation after revoke = 0
mutation after cancel fence = 0
automatic retry after revoke = 0
production authority registry = 0
pathname reopen = 0
unexpected workspace/profile exposure = 0
stale evidence accepted = 0
```

不适用写 `N/A — reason`。

---

# 15. Fail-closed

不得使用：
- probably pass
- seems safe
- mostly pass

关闭 required gate。

Evidence missing = BLOCKED。

---

# 16. Context / token discipline

- Coordinator 读取完整治理和开发上下文；
- Luna Max worker 只拿任务所需最小上下文；
- Sol Max 只拿压缩后的 Architect/Stage packet；
- Luna High 只拿独立 Gate packet；
- 不让所有代理重复扫描完整历史；
- 不把大量原始日志直接塞给 Sol Max；
- 可以引用仓库文档位置，避免重复复制全文。

节省 token 不能作为跳过 required evidence 的理由。

---

# 17. 阶段循环

```text
Sol Medium Coordinator
    ↓ sync Source of Truth
Stage Contract exists?
    ├─ no → Sol Max establishes Stage Contract
    └─ yes
        ↓
Luna Max workers
        ↓
blocker batching
        ↓
batch repair
        ↓
centralized build/test/canary/evidence
        ↓
Luna High gate
    ├─ BLOCKED_IMPLEMENTATION → batch repair → re-gate
    ├─ BLOCKED_ARCHITECTURE → consolidated packet → Sol Max
    └─ PASS
        ↓
Stage Closure Packet
        ↓
Sol Max closes architecture + defines next stage
        ↓
Coordinator executes next stage
```

---

# 18. 默认完成标准

一个阶段只有在以下条件满足时才算治理意义上的闭合：

- Stage Contract obligations 已满足；
- implementation 完成；
- required tests/canary/negative evidence 完成；
- Luna High 对 exact candidate 给出 PASS；
- required architecture blockers = 0；
- Sol Max 完成阶段架构闭合，并在需要继续开发时给出下一 Stage Contract。

代码编译成功本身不等于阶段闭合。

---

# 19. D32 阶段专用补充协议（保留的 §16.1）

以下内容只补充 D32 已批准 ADR 明确引用的聚合门槛与 release-evidence bootstrap 顺序。其余项目治理以本文件 0–18 节及 `AGENTS.md` v1.1 为准，角色映射见 `MODEL_ROUTING.md`；如有冲突，遵循用户当前指令、已批准 ADR/Frozen Invariants 和新协议的控制层级。

## 16.1 阶段级与多门禁任务的批量修复纪律

当任务跨越一个阶段、包含多个门禁、需要昂贵 build/real canary，或已经出现连续 repair 时，Codex MUST 采用以下顺序：

```text
Blocker Census
    -> Common-root clustering
    -> Batch Repair
    -> Full affected matrix
    -> Expensive build/real canary
```

### 16.1.1 Blocker Census

在修改代码前，Codex MUST 一次性盘点当前 candidate 的：

- 所有已失败、未建立或相互矛盾的 gate/evidence；
- 当前阶段与相邻阶段的实现、测试、fixture、validator 和报告；
- 最近相关提交引入的跨提交契约变化；
- governance、exact SHA、环境/工具链和资源清理方面的前置问题。

每个 blocker MUST 标注症状、证据位置、影响的 gate/mode、候选共同根因，以及它是 inherited、environmental、implementation 还是 architecture 问题。Census 完成前 MUST NOT 进入昂贵 build 或 real canary。

### 16.1.2 Common-root clustering

Codex MUST 按共同根因或共同契约聚类，而不是按第一次出现的错误逐个修补。一个 cluster 至少要列出：

- 根因与涉及的提交/模块；
- 受影响的相邻阶段、validator、positive/negative mode 和 cleanup 路径；
- 不可改变的 frozen invariant、authority、protocol 和 identity continuity；
- 需要一次性验证的完整影响范围。

如果发现安全或数据风险要求立即停止，Codex MAY 立即 fail closed；否则禁止采用 `gate fail -> fix one -> rerun expensive gate` 的循环。

### 16.1.3 Batch Repair 与跨提交契约检查

同一 cluster MUST 在一个逻辑 repair batch 中协调修复。Repair 前后 MUST 检查：

1. 当前改动与相邻阶段的输入/输出、状态机和生命周期契约；
2. 实现与 validator、evidence schema、fixture 断言之间的跨提交契约；
3. authority/revoke/cancel、错误/终态、provider/tool 两轮交互和资源清理语义；
4. 是否误把继承缺陷、环境失败或证据缺失伪装成单点实现修复。

Repair MUST NOT 通过弱化 invariant、放宽 validator、删除失败测试、用 mock 替代 required real canary 或改变 authority ownership 来消除 blocker。

### 16.1.4 Full affected matrix

Batch Repair 后 MUST 在昂贵 gate 前运行完整受影响矩阵，至少覆盖：

- 所有受影响 focused/regression tests；
- positive 与全部相关 negative modes；
- provider/tool two-turn contract 及终态/错误契约；
- provenance、canonical path、bundle hash/schema 校验；
- cancellation/revoke/recovery、cleanup、process/handle/thread/resource lifecycle；
- 相邻阶段与 validator 的跨提交回归。

单项 focused test 或某一个 mode 通过，不得代表整个矩阵通过。新 blocker 出现时，必须回到 Census 和 clustering，而不是直接再做一次单点修补。

### 16.1.5 Expensive build / real canary 前的聚合门槛

在启动昂贵 build 或 real canary 前，被指定的 Luna Max Worker MUST 出具一次聚合检查，至少确认：

```text
governance = current and applicable
exact SHA / working tree = recorded and clean
provenance schema / canonical paths = consistent
bundle hashes = verified
provider/tool two-turn contract = verified
mode matrix = complete for affected scope
cleanup/resource lifecycle = verified
```

任一项未建立证据时，状态是 `BLOCKED`，不得用 compile、fixture、mock 或上一 candidate 的结果替代。聚合检查通过后，才可执行昂贵 build/real canary；repair 后即使某个旧 gate 仍可复用，其受影响部分也 MUST 重新建立证据。

#### D32 release evidence 两阶段 bootstrap（唯一窄例外）

仅对 ADR-D32-RELEASE-EVIDENCE-BOOTSTRAP 与 ADR-D32-EVIDENCE-BUNDLE-V1 定义的 D32-A gate evidence bundle 首次生成，允许以下两阶段顺序；这不是 §16.1.5 聚合门槛 PASS，也不构成对其他昂贵 build 或 real canary 的豁免：

1. **Phase 0 — bootstrap 前检查与本地矩阵。** 在任何证据产出 release build 前，固定 runner `scripts/d32-phase0-matrix.ps1` 必须记录适用治理、exact candidate SHA/clean pre/post、caller-pinned toolchain profile（包括本次 PowerShell host image 的 path/hash/opened-handle identity）、精确锁文件及 canonical paths、外部全新 evidence output path，并实际执行 ADR-D32-PHASE0-TOOLCHAIN-PROFILE 的五个 fixture build phases、protocol/Vita/Host 全套本地测试及 named provider/two-turn、mode、cancel/cleanup 和相邻回归。Phase 0 仅允许这些本地 fixture/test 编译；不得运行 release build、D31 real-process/seeder、真实 provider request、interactive/physical capture 或 Host real canary。十个 D31 real-process 测试必须明确记作 `NOT RUN — deferred until validated bundle and full aggregate`；四个 D29G2 real-provider 测试记为 `NOT RUN — user-authorized provider required`；三个 interactive/physical capture 测试记为 `N/A — NOT RUN` 并记录原因；均不得记为 PASS。测试使用默认并行，不得全局添加 `--test-threads=1`。此阶段的 `bundle hashes` 必须明确记为 `PENDING`；Phase 0 不是 §16.1.5 aggregate PASS。实际 `--list` 与 ADR 固定 inventory 不一致时，必须在 release build 前停止。
   fixture manifest v3 的六个原始 `environment` 字段保持不变；caller-pinned profile/run 与完整 locked-fetch 命令、结果及 Cargo process identity 放在 external `fixture-build-provenance.json` v2 (`D32_FIXTURE_BUILD_PROVENANCE_V2`) sidecar。Phase0 record 精确绑定五个 fixture 与三组 fetch 的有序 stdout/stderr captures、hash/bytes/opened-handle IDs。
2. **Phase 1 — 唯一获准的证据产出与门槛恢复。** Phase 0 完整 code-owned record 及其外部 caller-pinned SHA/profile 均验证通过后，仅允许 D32 preflight attestor 执行 ADR-D32-EVIDENCE-BUNDLE-V1 指定的两条固定 locked release Cargo argv，为该 exact SHA 生成三件 artifact、manifest 和 sibling attestation。使用 Phase 0 绑定的 populated external `CARGO_HOME`，仅以 caller-pinned direct Cargo/Rust toolchain、已核验 native tool profile 与明确构造环境运行；`CARGO_NET_OFFLINE=true` 是环境输入，不得因此改写两条固定 Cargo argv。不得复用未经证明的 stale target outputs、prior candidate、mock 或 fixture 来代替本次命令及其输出证明。任一命令、process/tool/artifact identity 检查或 exact-SHA/clean pre/post 检查失败，立即为 `BLOCKED`。生成后立即验证 schema、candidate SHA、commands、hashes/bytes/file identities、flat-only layout、`runtime_resources = []`、Tauri shipping resource map 和 clean 状态；然后重新执行完整 §16.1.5 aggregate 检查，且 `bundle hashes = VERIFIED`。ValidateOnly 若未取得全部 aggregate inputs，只能报告 `ARTIFACT_ONLY`，不得声称 aggregate PASS。在此完整聚合通过前，不得运行任何后续昂贵 gate 或 real canary。该顺序不减少 real-canary、negative evidence 或最终冻结要求。

除上述精确限定的 Phase 0 local fixture/test preparation 与两个 Phase 1 证据产出命令外，§16.1.5 原有门槛保持不变；Phase 0 不是对 release build、D31 seeder、real canary 或其他构建的一般豁免。不得把此例外推广到其他候选 SHA、证据包或任务。

---
