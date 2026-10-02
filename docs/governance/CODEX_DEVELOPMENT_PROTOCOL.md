# CODEX_DEVELOPMENT_PROTOCOL.md

**Version:** 1.3 / 2026-10-02-efficiency-01
**Status:** Project Governance Baseline  
**Scope:** 虚拟生命项目后续全部开发阶段。

**强制执行补充与生效索引：** `EXECUTION_EFFICIENCY_POLICY.md`。本修订保留 v1.2 角色/工作区框架，补充可验收的 census、验证分层、attempt ledger 和静默窗口；D32 专项 frozen 条款不减。本文件同步通用治理规则；下方 D32 专项 supplement、既有 ADR/Frozen/SC-D32-V1 与 exact-SHA 历史仍按其各自 authority 管理。任何正式执行中的候选不得修改其 SHA 或 clean 状态。

## 0. 目的

让多 Agent 真正并行进行调查和代码产出，同时避免大型 Rust/Tauri 项目因多 worktree 重复编译造成磁盘与时间浪费。

当前模型职责：

- Sol Medium / GPT-6.1：Coordinator
- Luna Max / GPT-6：Worker
- Sol Max / GPT-6.1：Architect
- Luna High / GPT-6：Independent Gate

核心执行方式：

> **并行调查 / 并行 Patch Worktree → 单一 Integration Tree → 集中构建与门禁**

本协议重点避免：
- 子代理发现一个 blocker 就直接升级架构模型；
- blocker 一个一个 repair 导致重复编译；
- 每个 Agent 各自维护完整构建环境；
- worktree 无限增长导致目录和状态混乱；
- Coordinator 把 Worker 的实现方法规定过死；
- Sol Max 被用于执行期跟踪；
- Gate 只发现第一个 blocker 就退出。

除非用户明确覆盖，本协议为强制规则。

---

# 1. 规范词

- **MUST / MUST NOT**：强制 / 禁止。
- **SHOULD / SHOULD NOT**：默认要求；偏离需有明确工程理由。
- **PASS**：当前 exact Integration Candidate 满足指定 gate。
- **BLOCKED_IMPLEMENTATION**：架构不变即可 repair 的问题。
- **BLOCKED_ARCHITECTURE**：需要 Architect 决策的问题。
- **Stage Contract**：由 Sol Max 确立的阶段目标、范围、禁止项和 exit criteria。
- **Patch Worktree**：仅用于隔离并行代码修改的临时工作树，默认不构建。
- **Integration Tree**：唯一正常集成、编译、测试、canary、candidate commit 工作树。
- **Exact Candidate**：Integration Tree 上当前门禁对应的精确 Git SHA。
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
- 为每个 Worker 给出明确 Task Packet；
- 选择 READ_ONLY / PATCH_WORKTREE / INTEGRATION 模式；
- 管理最多 3 个 active Patch Worktree；
- 避免多个写 Worker 修改重叠核心代码；
- 汇总全部 blocker；
- 组织 batch repair；
- 汇聚 patch 到 Integration Tree；
- 指定 Integration / Build Owner；
- 组织集中 build/test/canary；
- 生成 Luna Gate Packet；
- 在 Architect 触发条件满足时生成压缩 packet；
- 阶段 gate 通过后准备 closure/next-stage packet。

MUST NOT：
- 自行创造/改变 frozen architecture；
- 自行弱化 invariant；
- 自行修改 authority/schema/migration/recovery/security/protocol 的冻结语义；
- 频繁轮询 Worker 或 Gate 进度；
- 用 Sol Max 做普通 blocker 分类；
- 把 Worker 当作逐步照抄指令的低自主执行器。

Coordinator 可以在已冻结架构内做普通工程与调度决策。

---

# 4. Worker — Luna Max

默认所有 Codex 工程 Worker 使用 Luna Max。

Worker MAY 承担：
- Scout；
- implementation；
- repair；
- tests/fixtures；
- canary implementation；
- evidence/root-cause analysis；
- read-only red-team；
- Integration / Build Owner（被明确指定时）。

Worker MUST：
- 只处理被分配范围；
- 遵守相关 invariant；
- 根据 Task Packet 在约束内自主决定具体做法；
- 将 findings/blockers 汇总返回 Coordinator；
- 在安全范围内尽量完成本轮调查再返回；
- 输出 changed files、patch/local commit、tests、风险、假设和 blocker set。

Worker MUST NOT：
- 直接调用/汇报 Sol Max；
- 自行修改 Stage Contract；
- 自行修改 frozen invariant；
- 删除/弱化失败测试获得 PASS；
- 无授权 push remote；
- 在普通 Patch Worktree 中执行正常 build/test/canary。

---

# 5. Worker Task Packet — 高约束目标，低约束实现

Coordinator MUST 给每个 Worker 提供足够明确但不过度规定实现方法的任务包。

Task Packet 至少包括：

- Role；
- Execution mode；
- Goal；
- Current stage；
- Relevant context；
- Frozen constraints；
- Allowed modification scope；
- Required outputs/evidence；
- Blocker policy；
- Build policy；
- Stop conditions。

默认原则：

> **Sol Max 决定 WHAT MUST BE TRUE。**

> **Sol Medium 决定 WHAT WORK NEEDS TO BE DONE。**
> **Luna Max 决定 HOW TO DO IT。**

只有以下情况 SHOULD 指明具体实现做法：
- Sol Max 已冻结该实现路径；
- 已知历史坑必须明确禁止；
- repair 针对一个已定义 closure proof 的 blocker。

标准模板：
`templates/WORKER_TASK_PACKET.md`

---

# 6. Blocker batching

发现 blocker 不等于立即 repair。

每轮 Worker/Reviewer：

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

# 7. Parallel Workspace Policy

多 Agent 优势主要来自**并行调查和并行代码产出**，不是并行完整构建。

## 7.1 READ_ONLY

适用：
- Scout；
- root-cause investigation；
- evidence analysis；
- red-team；
- architecture impact discovery。

直接共享仓库只读视图，不创建 worktree。

## 7.2 PATCH_WORKTREE

当多个 Luna Max 需要并行修改互不冲突的代码时使用。

规则：

1. 最多 **3 个 active Patch Worktree**；
2. 达到上限不得创建第 4 个，必须先完成/回收已有 slot；
3. Coordinator 管理 active registry；
4. 推荐命名：
   `<stage>-w<n>-<short-task>`
5. SHOULD 使用仓库外固定根目录，例如：
   `<repo-parent>/.<repo-name>-worktrees/`
6. Patch Worktree 只用于：
   - edit；
   - git diff/status；
   - 必要的低成本静态检查；
   - patch/local commit 产出。
7. 默认禁止：
   - 正常 `cargo build/test`；
   - Tauri full build；
   - real canary；
   - final candidate validation。
8. 不得长期积累：
   - `target/`；
   - release artifacts；
   - 大型临时构建目录。
9. patch 被集成或任务放弃后 MUST remove；
10. SHOULD 执行安全的 `git worktree prune` 清理 stale metadata。

Patch Worktree 是临时资源，不是长期开发环境。

## 7.3 INTEGRATION

必须存在唯一正常 Integration Tree。

只有 Integration Tree 负责：

- 批量应用/合并 Worker patch；
- mechanical conflict resolution；
- candidate commit；
- `cargo check/build/test`；
- broader/full suite；
- real canary；
- exact SHA evidence；
- Luna High gate。

Luna High 只审 Integration Candidate，不审各 Patch Worktree branch。

## 7.4 ISOLATED_BUILD_WORKTREE

只在两个互斥方案必须通过真实隔离构建/运行才能判断时使用。

必须：
- Coordinator 明确批准；
- 临时创建；
- 使用独立 `target`；
- 不与 Integration Tree 并发共享同一 `CARGO_TARGET_DIR`；
- MAY 复用安全的 compiler cache（如项目环境已配置）；
- 验证结束后清理。

这是例外模式，不是普通 Worker 默认模式。

---

# 8. Integration / Build Owner

Coordinator MUST 指定一个 Luna Max 作为当前唯一 Build Owner；Coordinator/Root 不默认代替 Worker 执行实现、构建或普通测试分析。

推荐 Build Wave：

`parallel analysis/edit -> blocker batch -> patch batch -> integration -> focused check/test -> broader suite -> real canary`

Build Owner MUST：
- 确认应用 patch 的基线；
- 优先发现 patch overlap/冲突；
- 机械冲突自行解决；
- 如果两个 patch 隐含互斥架构假设，返回 Coordinator 分类；
- 保持 Integration Tree 与 candidate evidence 可审计。

MUST NOT：
- 为每个小 blocker 重复完整构建；
- 默认执行 `cargo clean`；
- 把 Patch Worktree 的局部成功当成最终 candidate evidence。

除非技术必要或用户明确要求：

> **MUST NOT run `cargo clean` or equivalent cache reset.**

---

# 9. Architect — Sol Max

Sol Max 使用当前可用最高 Sol 推理等级，负责高信息密度架构任务。

只处理：

## A. Stage Contract
- 当前阶段没有有效 Contract；
- 上一阶段闭合且用户允许继续后需要确立下一阶段；
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
- blocker 批次共同根因是冻结架构冲突；
- Luna High 返回 `BLOCKED_ARCHITECTURE`；
- 高可信证据证明现有 contract 本身不成立。

## D. Stage closure
阶段 gate PASS 后：
- 判断 architecture obligations 是否闭合；
- 明确哪些决定 frozen；
- 判断是否需要 repair stage；
- 用户允许继续时确立下一 Stage Contract；当前 D32 closure 后清理并停止，不建立 D33。

Sol Max MUST NOT：
- 跟踪 Worker/Luna 进度；
- 管理 worktree slot；
- 逐个查看普通 blocker；
- 指挥常规 repair；
- 做普通 compile/test 分析；
- 重复 Luna High 的实现级 whole-candidate gate。

本协议不规定 Sol Max 固定调用次数。是否调用由职责和触发条件决定。

---

# 10. Independent Gate — Luna High

Luna High 与 Luna Max implementation context 必须逻辑隔离。

输入只针对最终 Integration Candidate，重点包括：
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

# 11. Gate 后路由

## BLOCKED_IMPLEMENTATION
Coordinator：
- 汇总 blocker set；
- 由 Luna Max 批量 repair；
- 必要时重新分配 Patch Worktree；
- 集成 patch；
- 产生新 exact Integration Candidate；
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
- 确认所有临时 Patch Worktree 已集成或清理；
- 生成 Stage Closure & Next Stage Packet；
- 交 Sol Max 做阶段架构闭合；仅用户允许继续时确立下一阶段，当前 D32 完成后停止。

---

# 12. Source of Truth

按 `PROJECT_SOURCE_OF_TRUTH.md` 自动发现和同步。

特别规则：

- Git actual state 决定代码现实；
- Frozen decisions/invariants 决定规范边界；
- Sol Max Stage Contract 决定正式阶段目标；
- latest verified development document 辅助恢复开发上下文；
- `CURRENT_DEVELOPMENT_STATE.md` 只是缓存；
- Patch Worktree branch/commit 只是候选 patch 来源，不是最终项目状态。

不得只按文件名/修改时间猜“最新”。

---

# 13. Git discipline

Gate 前 MUST 记录：
- branch；
- base；
- parent；
- Integration candidate；
- merge-base（适用时）；
- Integration working tree。

规则：
- Gate 只绑定 Integration exact SHA；
- repair 后新 SHA 重新 gate；
- dirty Integration Tree 不可 final freeze；
- 默认本地 commit；
- 未经用户明确要求不 push remote；
- Patch Worktree branch/commit 不自动具有 gate/freeze 权威；
- 阶段闭合前临时 worktree 必须被集成、明确保留理由或清理。

---

# 14. Real Canary

明确要求真实 Host/OS/filesystem/SQLite/process/toolchain/crash 行为时：

- mock PASS ≠ real canary；
- fixture PASS ≠ real canary；
- compile PASS ≠ real canary；
- Patch Worktree 的局部运行结果 ≠ 最终 Integration Candidate canary。

无法建立 required real canary：
`BLOCKED_IMPLEMENTATION`，除非根因是 architecture contract 本身不可实现，此时升级为 `BLOCKED_ARCHITECTURE`。

---

# 15. Negative Evidence

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

# 16. Fail-closed

不得使用：
- probably pass
- seems safe
- mostly pass

关闭 required gate。

Evidence missing = BLOCKED。

---

# 17. Context / token discipline

- Coordinator 读取完整治理和开发上下文；
- Luna Max Worker 只拿 `WORKER_TASK_PACKET` 所需最小上下文；
- Sol Max 只拿压缩后的 Architect/Stage packet；
- Luna High 只拿独立 Gate packet；
- 不让所有代理重复扫描完整历史；
- 不把大量原始日志直接塞给 Sol Max；
- READ_ONLY Worker 优先引用代码/文档位置；
- Patch Worker 只接收相关 scope 与 frozen constraints；
- 节省 token 不能作为跳过 required evidence 的理由。

---

# 18. 阶段循环

```text
Sol Medium Coordinator
    ↓ sync Source of Truth
Stage Contract exists?
    ├─ no → Sol Max establishes Stage Contract
    └─ yes
        ↓
parallel task decomposition
        ↓
READ_ONLY workers + up to 3 PATCH_WORKTREE workers
        ↓
blocker batching / patch batching
        ↓
single Integration Tree
        ↓
Integration / Build Owner
        ↓
focused build/test → broader suite → real canary/evidence
        ↓
Luna High gate
    ├─ BLOCKED_IMPLEMENTATION → batch repair → integrate → re-gate
    ├─ BLOCKED_ARCHITECTURE → consolidated packet → Sol Max
    └─ PASS
        ↓
cleanup/resolve temporary worktrees
        ↓
Stage Closure Packet
        ↓
Sol Max closes architecture + defines next stage only when continuation is authorized (D32: stop after closure and cleanup)
        ↓
Coordinator executes next stage
```

---

# 19. 默认完成标准

一个阶段只有在以下条件满足时才算治理意义上的闭合：

- Stage Contract obligations 已满足；
- implementation 完成；
- required tests/canary/negative evidence 完成；
- Luna High 对 exact Integration Candidate 给出 PASS；
- required architecture blockers = 0；
- 临时 Patch Worktree 已集成或清理；
- Sol Max 完成阶段架构闭合，并在需要继续开发时给出下一 Stage Contract。

代码编译成功本身不等于阶段闭合。

---

# 20. D32 阶段专用补充协议（保留的 §16.1）

以下内容只补充 D32 已批准 ADR 明确引用的聚合门槛与 release-evidence bootstrap 顺序。其余项目治理以本文件 0–19 节及 `AGENTS.md` v1.3 / `2026-10-02-efficiency-01` 为准；模型信号映射见 `MODEL_ROUTING.md`，通用角色边界以当前 AGENTS.md 与本协议为准；如有冲突，遵循用户当前指令、已批准 ADR/Frozen Invariants/Stage Contract 和本协议的控制层级。

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
   fixture manifest v3 的六个原始 `environment` 字段保持不变；caller-pinned profile/run 与完整 locked-fetch 命令、结果及 Cargo process identity 放在 external `fixture-build-provenance.json` v6 (`D32_FIXTURE_BUILD_PROVENANCE_V6`) sidecar。Phase0 matrix 为 V6；release attestation 为 V7，post-bundle aggregate 为 V6。D31 recovery-seeder provenance V2、profile V2 与 debug/Job trace V2 保持不变。每个 reader/consumer 严格拒绝旧版与未知版本。EvidenceRoot 必须是新建、独占、canonical、external、non-reparse 的目录；create-new owner marker 绑定 exact candidate、caller-pinned profile identity、root opened-handle identity 与完整 lowercase 32-hex `run_id`。Cargo home 和 TEMP 固定为 `EvidenceRoot\r\c` 与 `EvidenceRoot\r\t`，且 CARGO_HOME 在 fetch 前必须为空。不得使用 junction、`subst`、系统 LongPaths policy、alternate source、reused cache，或更改 fixed Cargo argv/toolchain/trace，除第 3 点对五个 fixture build 的 jobs/timeout 窄例外。Phase0 完整 code-owned record 绑定五个 fixture 与三组 fetch 的有序 stdout/stderr captures、hash/bytes/opened-handle IDs。owner marker 成功建立后，早期失败可 create-new 写 `D32-PHASE0-BLOCKED-DIAGNOSTIC.json` (`D32_PHASE0_BLOCKED_DIAGNOSTIC_V1`)；它只记录失败/trace/cleanup/capture evidence，无 PASS/Gate authority，Phase 1 与 aggregate 对其存在一律拒绝。若失败诊断无法持久化，保留 primary error 并追加 capture error；缺失证据不得推断 cleanup/PASS。

   Sol Max 对 locked vendored protoc 的精确 D32 Phase0/Phase1 例外另行批准：Phase0 外部 create-new authority V1 由 Coordinator 独立钉住 SHA；仅接受 Vita `Cargo.lock` 中两个 exact 3.2.0 crates.io 包及其批准 checksums、fresh owner-bound CARGO_HOME 的唯一 canonical registry source slot、唯一 regular `bin/protoc.exe`（11,934,496 bytes，SHA-256 `cbd1ca1fd6afd1bb6ddd1c09c118ecd4c50f928980857f16fe6fc23704ea17e2`）和每次运行的独立 grant V1。runner 只能在三次固定 fetch 后以进程内、no-overwrite方式校验/物化锁定 archive，不得调用 tar/helper、增加 Cargo argv、复制或切换 source。只对固定 `src-tauri` Cargo build/test/release 命令注入精确 `PROTOC`；Vita code-mode 不接收该变量。每个 CREATE 在 Continue 前仍须验证 grant 绑定的 candidate/Profile/owner/run/root/home/archive/extracted-image opened identities、父链与 non-breakaway Job；其他 helper 和 ambient resolution 一律保持拒绝。另有 Sol Max 批准的精确 source-patch 与 H7-C 例外：仅接受经独立 caller-pinned `D32_TAURI_MACROS_SOURCE_PATCH_V1` 证明的 tauri-macros 2.6.3 原始锁定 archive、唯一 candidate-local wrapper patch 和关联 Cargo metadata；仅固定 Vita full-local suite 可以从 owner-bound TempRoot 的 35 个预创建 slot 中启动 exact pinned Git.exe。Coordinator authority 在运行前绑定 candidate/Profile、EvidenceRoot/TempRoot 路径、Git opened identity 和有限固定 Git 命令/environment/suite policy；runner 在 fresh owner/run/root/temp 身份建立后写 create-new per-run grant，Continue 前验证 Git opened image/argv/cwd/environment/slot 与直接父链和同一 nonbreakaway Job。No test-to-process attribution is asserted; a separate D32 companion attestation binds all 46 fixed H7-C result rows and every observed Git identity to V2 trace. No shell, arbitrary Git, helper or ambient child is admitted, and no Cargo argv/target/features/toolchain/fixture/suite is changed.
   Phase0/Phase1 authority 不适用于 D31 recovery seeder。获准的 D31 扩展必须另用 seeder fresh run/home、owner marker 和 per-run grant，并以独立 D32 companion attestation 链接未改动的 D31 provenance V2 与 artifact；不得重放 Phase0 grant。fixture provenance/Phase0/release attestation/aggregate 的当前 V6/V6/V7/V6 schemas 严格拒绝旧版与未知版；Profile V2、Trace V2、fixture manifest v3、D31 seeder provenance V2 不变。
2. **Phase 1 — 唯一获准的证据产出与门槛恢复。** Phase 0 完整 V6 code-owned record 及其外部 caller-pinned SHA/profile 均验证通过，且不存在 blocked-diagnostic sidecar 后，仅允许 D32 preflight attestor 执行 ADR-D32-EVIDENCE-BUNDLE-V1 指定的两条固定 locked release Cargo argv，为该 exact SHA 生成三件 artifact、manifest 和 sibling attestation。attestation schema/type 为 V7。使用 Phase 0 绑定的 populated external `CARGO_HOME` 与同一 per-run protoc grant；仅以 caller-pinned direct Cargo/Rust toolchain、已核验 native tool profile 与明确构造环境运行；`CARGO_NET_OFFLINE=true` 是环境输入，不得因此改写两条固定 Cargo argv。不得复用未经证明的 stale target outputs、prior candidate、mock 或 fixture 来代替本次命令及其输出证明。任一命令、process/tool/artifact identity 检查或 exact-SHA/clean pre/post 检查失败，立即为 `BLOCKED`。生成后立即验证 schema、candidate SHA、commands、hashes/bytes/file identities、flat-only layout、`runtime_resources = []`、Tauri shipping resource map 和 clean 状态；然后重新执行完整 §16.1.5 aggregate 检查，aggregate schema/type 为 V6 且 `bundle hashes = VERIFIED`。ValidateOnly 若未取得全部 aggregate inputs，只能报告 `ARTIFACT_ONLY`，不得声称 aggregate PASS。在此完整聚合通过前，不得运行任何后续昂贵 gate 或 real canary。该顺序不减少 real-canary、negative evidence 或最终冻结要求。

3. **Approved bounded fixture-build budget clarification (ADR-D32-PHASE0-FIXTURE-BUDGET-V1).** For current prospective implementation and any newly produced evidence, this narrow approval supersedes the preceding version-number and fixed-fixture-argv statements only as follows: the exact three ordered locked fetch commands and all non-fixture Phase0 commands retain a 14,400-second timeout; the Phase0 default remains 1,800 seconds, and a formal invocation must explicitly pin `-Phase0TimeoutSeconds 14400` and `-Phase0FixtureBuildTimeoutSeconds 28800`. Only the five existing ordered fixture `cargo build` commands may change `--jobs 1` to `--jobs 4`, each with its own 28,800-second timeout. The H7 authority suite remains at 14,400 seconds. Before Cargo, the runner records and enforces at least 8 logical CPUs, 12 GiB available physical RAM, 200 GiB free on the evidence volume, and zero competing target writers; because the Windows process census lacks a reliable working directory, any active Cargo/rustc/cl/link/build-script process is conservatively treated as a possible target writer. Inability to measure is BLOCKED. Keep the new empty owner-bound CargoHome/TempRoot, normal target directories, exact toolchain, V2 Job/debug/identity/cleanup rules, fixed fixture/test inventory, and existing five-output quarantine scope. Do not copy old caches, override target-dir, run `cargo clean`, or apply this budget to tests, Phase1, the D31 seeder, standalone/default fixture work, or another candidate. Standalone/default fixture work remains 600 seconds/jobs=1 and cannot attest Phase0. Current strict schema versions are fixture provenance V6, Phase0 V6, release attestation V7, and aggregate V6; prior V5/V5/V6/V5 and unknown versions are rejected. Fixture manifest v3 with its six original environment fields, Profile V2, Trace V2, authorities V1, and D31 seeder provenance V2 are unchanged.

4. **Approved candidate-bound test-inventory authority clarification (ADR-D32-PHASE0-TEST-INVENTORY-AUTHORITY-V1).** This prospective clarification supersedes only the earlier code-authored fixed `--list` inventory comparison and the earlier list-command timeout language. Before a formal Phase0 run, a separate monitored list-only discovery runs in a fresh external owner-bound root/CargoHome/TempRoot on the same clean exact candidate/Profile V2/locks/source pin. It performs the three unchanged fixed locked fetches (14,400 seconds), then exactly six ordered list-only commands (protocol all/ignored, Vita all/ignored, Host all/ignored). Each list command adds only `--jobs 4` before `--` and explicitly uses `Phase0InventoryListTimeoutSeconds=28800`; no test body runs in discovery. The V2 trace/Job/process identity/cleanup rules remain exact; discovery uses a separate discovery-only protoc authority/grant and no H7 Git authority. It produces `D32_TEST_INVENTORY_DISCOVERY_V1` with `gate_authority=NONE` and complete strict-parsed rows, summaries, raw stream refs/hashes/bytes/opened identities, process records and exact candidate pre/post. A separate create-new `D32_TEST_INVENTORY_BASELINE_V1` remains `AWAITING_COORDINATOR_PIN` with `gate_authority=NONE`; only after independent source/manifest/config and discovery review does the Coordinator pin its external path/SHA. Formal Phase0 requires this external pin before claiming its root, reopens and validates the pair, reruns all six exact list commands, and compares every row/category/count/digest before suites; full and focused results reconcile by complete names/category/status, not counts alone. Release, aggregate and independent-gate consumers independently revalidate both references and same-candidate/profile bindings. The new strict schema sequence is discovery V1, baseline V1, Phase0 V7, release attestation V8, aggregate V7. Fixture provenance V6, manifest v3 with its six fields, Profile V2, Trace V2, source/protoc/H7 authorities V1, bundle manifest v1 and D31 seeder provenance V2 remain unchanged; all prior/unknown schemas reject. This approval does not reduce any fixture, suite, focused check, negative evidence, Phase1 command or downstream gate and authorizes no discovery/Cargo/formal Phase0/root/authority creation by itself.

除上述精确限定的 Phase 0 local fixture/test preparation、六个 candidate-bound inventory listing commands 与两个 Phase 1 证据产出命令外，§16.1.5 原有门槛保持不变；Phase 0 不是对 release build、D31 seeder、real canary 或其他构建的一般豁免。不得把此例外推广到其他候选 SHA、证据包或任务。

## Approved PowerShell module-content admission addendum (ADR-D32-POWERSHELL-MODULE-CONTENT-AUTHORITY-V1)

For newly produced D32 evidence, the external create-new `D32_POWERSHELL_MODULE_CONTENT_AUTHORITY_V1` schema-1 record must be independently path/SHA-pinned by the Coordinator before a real D32 runner imports any installed module. It binds exact candidate/repository, Profile V2, PowerShell host/PSHOME identities and only the fixed ordered Management → Utility → CimCmdlets roles. Each role authority contains the complete import-time content/dependency closure with exact manifests and root/nested/required-module/script/assembly relationships, canonical file path, bytes, SHA-256, volume serial and 128-bit file ID, plus deterministic complete inventory digests. Ambient PSModulePath, module autoload, name/version/signature/prefix/wildcard matching and any path-only trust are not content authority. The OS/CLR/PowerShell Core and candidate-owned module-free bootstrap remain the bounded base; this is not a hermetic claim.

Every accepted entry must be a fresh direct invocation of the exact caller-pinned PowerShell host with `-NoProfile -File <current exact runner>` and only finite documented, non-ambiguous switches. Before the first module import the bootstrap disables autoload; validates actual `-File` operand, Profile/auth/Git/candidate/repository pins and cross-bindings using module-free .NET/Core; obtains stable identity/content handles and ancestor fences for the full module closure; then imports only the three fixed manifests in order and records verified loaded modules, assemblies and effective command origins. Hashing and releasing files before a path-based import is not sufficient. Reuse and phase boundaries revalidate retained fences and all independent caller pins, and fail closed if write/replace/redirect cannot be excluded. No install, ACL or OS changes are allowed.

No-pin runs are restricted to module-free bootstrap/schema/negative tests and must record `import_attempts=0`; they may not import a module, start a child, run Cargo/network, claim a formal root, or claim a gate. The former no-pin real-module SelfTest exception is cancelled. Real SelfTest/LoaderSelfTest requires the same Profile V2 and content admission before module import, and mode-required Git/Profile pins are checked before import. A script that rejects startup configuration after execution begins cannot claim that startup was prevalidated or that a pre-import marker count was zero. Candidate/facts generators that run before admission stay module-free and may emit only untrusted candidates.

Every producer embeds a strict `D32_POWERSHELL_MODULE_ADMISSION_V1` record in its existing evidence. It binds the independent authority/Profile/Git references, actual runner process identity, startup switches, entry-script content identity, admission/module closure/import order and actual module/assembly/command-origin verification. Baseline V2 carries the discovery producer admission and its own distinct baseline producer admission. Phase0, release and aggregate consumers validate the relevant admissions against the exact current candidate and caller-pinned module authority; omitted, copied-as-own, prior, unknown, stale or tampered admission is BLOCKED.

The current strict schema sequence is fixture provenance V7, discovery V2, baseline V2, Phase0 matrix V8, release attestation V9 and aggregate V8. The older version numbers still printed in historical paragraphs above describe prior decisions only and are superseded prospectively by this sequence. Profile V2, Trace V2, fixture manifest v3 and its six environment fields, bundle manifest v1, source/protoc/H7 authority V1, owner marker, failure-only blocked diagnostic V1, D31 seeder provenance V2 and Host consumer remain unchanged. The SC-D32-V1 ordered sequence, exact argv/jobs/deadlines, five fixture phases, full local suites/focused checks, V2 Job/cleanup requirements, fresh roots and quarantine scope are unchanged. Future D31 companion evidence must bind its seeder process admission; this decision does not change Host consumption. No D33 work is established.

Required positive/negative evidence is defined by the ADR. In particular, every pre-import rejection records zero import attempts; loader cases also record zero marker/child/Cargo and no formal root. Content-drift and replacement-window negatives use synthetic/record mutations only and never modify installed PowerShell files. If any required content or ancestor fence is unverifiable, status is BLOCKED. This addendum authorizes implementation and no-Cargo validation only; it does not authorize discovery, formal Phase0, authority creation, release build, canary, gate or stage closure.

## Approved PowerShell module-content admission V2 supersession

ADR-D32-POWERSHELL-MODULE-CONTENT-AUTHORITY-V2 prospectively supersedes V1's PSHOME path-only trust assumption and blanket directory-share/whole-namespace-freeze proof method. V1's independent caller pins, no-pin restrictions, exact direct -NoProfile -File startup requirements, fixed Management → Utility → CimCmdlets imports, module-free-before-import order and downstream evidence-chain obligations remain active except where the record schema is explicitly replaced. No prior evidence is rebound.

Before any installed module import, a Coordinator must independently pin the exact path/SHA of a create-new strict D32_POWERSHELL_MODULE_CONTENT_AUTHORITY_V2 schema-2 document. It binds exact clean candidate SHA, canonical repository, Profile V2 path/hash/bytes/opened identity, exact pwsh host and PSHOME identities, the full finite installed PSHOME tree, its protected namespace, fixed resolver policy and exact three module closures. The candidate generator is module-free and grants no authority. The record binds each file's canonical path, bytes, SHA-256, volume/file ID, owner SID and exact security descriptor; every directory binds canonical path, opened identity, owner and descriptor. It includes a deterministic complete inventory digest and the protected ancestors. Any reparse point, alias, incomplete enumeration, content/identity/ACL mismatch or untrusted effective writer is BLOCKED.

Only explicitly trusted installation maintainers (SYSTEM, TrustedInstaller and trusted elevated Administrators) may have effective namespace write/replace/delete/rename/reparse/attribute/DACL/owner authority. The normal run is unprivileged; the runner queries and records process-token elevation/integrity, rejects elevated/high-integrity/system tokens and thread impersonation, and revalidates token state on reuse. Unknown trustees and the ordinary/current user cannot self-designate trusted. No runtime maintenance may occur during admission. Retained handles prove stable object identity, not a whole-directory lock. Protected descriptor and ancestor/path checks establish the writer boundary. Unrelated additions outside a resolver namespace need not be forbidden; any addition that could enter PSHOME module, managed, or native resolution must be included in the pinned complete tree or rejected before use.

Admission disables module autoload, replaces PSModulePath with the exact PSHOME Modules path, then uses module-free .NET/Core to validate startup, true current File operand, caller pins, Profile/authority/Git cross-bindings, complete distribution content and namespace descriptors, and resolver inputs before any module cmdlet or import. Resolver evidence must account for TPA/deps/runtimeconfig inputs, startup hooks/profiling, loaded managed/native images, and process-local native search configuration. Managed/native resolution is confined to the independently pinned protected PowerShell distribution plus trusted Windows OS/CLR/Core. CWD, PATH, user module paths and arbitrary external assemblies are not trusted. Safe DLL-search APIs must be configured and their actual domain checked; simply calling an API is not proof. Any unknown resolver input, preloaded external image, stale policy or inability to prove exclusion fails before import with import_attempts=0.

Only after all pre-import checks pass may the three fixed manifests import, in Management → Utility → CimCmdlets order. The runner verifies loaded module, assembly, command and native origins. Library reuse and phase boundaries revalidate external pins, actual runner/startup/entry identity, full-distribution content/ACL/object fences, PSModulePath/autoload and resolver policy. Mutable global state, module names and paths cannot create authority. Direct startup remains the exact pinned pwsh host with -NoProfile -File and a finite unambiguous documented switch set; reject ConfigurationFile, command/encoded-command modes, wrapper/session starts, unknown/ambiguous switches and a wrong or relative File operand. A script that rejects startup configuration after it has begun cannot claim pre-startup prevention or a zero pre-import marker.

The former no-pin real-module SelfTest exception remains cancelled. Real SelfTest/LoaderSelfTest requires Profile and content admission before imports even when mode-required Git/Profile pins are missing; such missing pins reject first. No-pin work is limited to module-free schema/bootstrap/synthetic negatives and explicitly records import_attempts=0. It may not import modules, start children, run Cargo/network, claim a formal root or claim a gate.

All producers embed strict D32_POWERSHELL_MODULE_ADMISSION_V2 schema-2 records in existing evidence. They bind independent authority/Profile/Git references, actual runner process and non-elevated token state, startup/entry, full-distribution and namespace digests, resolver inputs/policy, module closure/import order and actual origins. Every current producer, reader, validator, inline fixture, nested reference and gate reader rejects admission V1, prior/unknown, omitted, copied-as-own, stale, malformed or tampered evidence. Baseline V2 binds discovery's producer admission and a distinct baseline-producer admission. No per-run companion is added.

The outer strict schema sequence is unchanged: fixture provenance V7, discovery V2, baseline V2, Phase0 matrix V8, release attestation V9 and aggregate V8. Profile V2, Trace V2, fixture manifest v3 and its six fields, bundle manifest v1, source/protoc/H7 authority V1, owner marker, failure-only blocked-diagnostic V1, D31 seeder provenance V2 and Host consumption remain unchanged. The complete SC-D32-V1 sequence, exact argv/jobs/deadlines, all five fixtures, complete suites/focused checks, V2 Job cleanup, fresh roots and quarantine scope are not reduced or reordered. Future D31 companion evidence binds the seeder process admission without changing Host consumption.

Required negatives use record mutations or synthetic fixtures only; never write, replace or change ACLs on installed PowerShell files. Cover absent/wrong/self-derived pins; prior/unknown/duplicate/wrongly typed fields; distribution, manifest, module/DLL/nested dependency bytes/hash/identity/inventory drift; owner/ACL/token/ancestor violations; reparse/escape/alias/namespace additions; ambient autoload/PSModulePath, shadows, startup injection and wrong host/File operand; managed/native/CWD/PATH resolver escapes; stale/forged/cross-process reuse; and downstream missing/tampered admissions. Every pre-import rejection records import_attempts=0 and applicable loader failures record marker=0, child/Cargo=0 and formal-root=false. Positive full real-module admission, exact import origins, library reuse, cross-process records and the full discovery→baseline→Phase0→release→aggregate chain remain required before a D32 gate.

This V2 approval grants implementation and module-free/no-Cargo validation only. It does not authorize authority use/creation, discovery, formal Phase0, root claim, Cargo/fetch, release, canary, Luna High gate, stage closure, D32 PASS or D33 work. Missing real positive evidence remains BLOCKED.

### V2 prospective Windows component clarification — 2026-09-30

Windows OS/CLR/Core membership is established by verified component identity, not `%SystemRoot%` path alone. The module-free pre-import proof binds the `GetWindowsDirectoryW` result to process `SystemRoot`, the opened Windows-root identity, current OS version, protected relevant directory/ancestor namespace, and exact bytes/hash/file identities/owner/security-descriptor digests for actual Windows native and managed resolver files. The resolver policy carries exactly two ordered OS-security roles: `MICROSOFT_WINDOWS_OS_INSTALLATION` and `MICROSOFT_WINDOWS_DEFENDER_PLATFORM`.

The Defender role binds the exact versioned platform root and opened ancestor identities, complete finite file/directory inventory and deterministic digest, plus exact actual native-image references. Source proof verifies the version-matched `MpOav.dll` and `MPCLIENT.DLL` with cache-only WinVerifyTrust evidence for the expected Microsoft Windows signer/issuer. The platform directory is not added to ordinary DLL search; signature, basename or path alone grants no authority, and the component list cannot expand after import. Any fresh controlled process with an RTSS hook is blocked even if the hook is signed and its file namespace is protected.

The ProgramData exception remains exact and separate: only its observed limited metadata/unrelated-child rights may be tolerated, with SYSTEM ownership, an exact bound full descriptor, and the existing protected `C:\ProgramData\Microsoft` child identity/descriptor proving no deletion, replacement, rename or redirection. ProgramData itself need not have its DACL marked protected; its observed ACL policy remains independently enforced, and it does not receive the volume-root allowance. Delete-child/delete, reparse, DACL/owner changes and every other effective untrusted write remain blocked. Retained handles witness object identity, not a whole-namespace freeze.

The narrow ADR V2 volume-root clarification additionally permits only an untrusted effective `0x4` directory-child creation right at the opened local volume root containing the independently pinned current PowerShell host/PSHOME. That exact root's canonical path, volume/file identity, directory type, owner, and full present/non-null/protected descriptor must be in the independently pinned complete distribution ancestor inventory. It is not a resolver namespace: absolute pinned PSHOME/System32 and finite TPA/deps/runtimeconfig inputs, disabled ambient/CWD/PATH resolution, and exact origin checks must reject any new sibling before use. All existing child chains remain independently protected against delete/replace/rename/redirect. No `0x2` file creation/AppendData, metadata, delete-child/delete, reparse, DACL/owner, generic-write/all, other volume/UNC/nested ancestor, or ProgramData rights are covered. Actual opened object facts and exact resolver evidence are required; a path, signature, caller Boolean, or retained handle alone is insufficient.

Shared admission V2 requires `resolver_admission.os_security_inventory_sha256` and complete exact native-origin file references in `import_verification.native_modules`; authority, reuse, downstream context comparison bind source/component, bytes/hash, volume/file ID, owner and descriptor digest. Missing-proof V2 drafts reject without compatibility. Outer evidence schemas and every SC-D32-V1 step remain unchanged. This clarification authorizes module-free/no-Cargo implementation validation only; fresh Profile/content-authority inputs must be repinned for the new exact SHA, and no discovery, Cargo, formal root, release, canary, gate, D32 PASS or D33 work is authorized.

---
