# AGENTS.md — 虚拟生命项目 Codex 根治理入口

**Protocol:** v1.3 / 2026-10-02-efficiency-01
**Scope:** 仓库根目录及全部子目录。
**Full protocol:** `docs/governance/CODEX_DEVELOPMENT_PROTOCOL.md`

**Execution rules / effective-source index:** `docs/governance/EXECUTION_EFFICIENCY_POLICY.md`。首次接手 MUST 完整读取。D32 历史 ADR/Stage Contract 在实际 Integration 目录，不能被此目录的历史空索引替代；不得在正式执行中修改其 exact-SHA candidate。

## 1. 当前模型映射

本项目当前模型信号由用户配置为 GPT-6 系列：

- **Coordinator:** Sol Medium / GPT-6.1
- **Architect:** Sol Max / GPT-6.1
- **Codex Worker:** Luna Max / GPT-6
- **Independent Gate:** Luna High / GPT-6

核心原则：

> **Sol Medium 协调；Luna Max 执行；Sol Max 定架构与阶段；Luna High 独立门禁。**

角色定义优先于未来具体模型名；模型名称变化时保持职责不变，除非用户明确更新治理规则。

## 2. 每次开发开始 MUST

Coordinator MUST：

1. 读取 Git branch / HEAD / working tree；
2. 读取：
   - `docs/governance/PROJECT_SOURCE_OF_TRUTH.md`
   - `docs/governance/CURRENT_DEVELOPMENT_STATE.md`
   - `docs/governance/FROZEN_INVARIANTS.md`
   - `docs/governance/ARCHITECTURE_DECISIONS.md`
3. 自动发现并核验当前开发总文档、阶段报告和最新 exact-SHA 证据；
4. 确定 `CURRENT_STAGE` 与有效 Stage Contract；
5. 拆分可并行任务，并为每个 Worker 选择执行模式；
6. YELLOW/RED、架构争议、门禁或阶段切换时读取完整协议。

首次接手与治理修订变化 MUST 完整读取；后续同修订按文件 fingerprints 核验变化和任务依赖，避免反复复制全部历史。运行状态缓存必须标明核验范围，不从过时状态页重做任务。

`CURRENT_DEVELOPMENT_STATE.md` 只是缓存，不得覆盖 Git 与已验证证据。

## 3. 角色边界

### Sol Medium / Coordinator
负责：
- 日常任务拆分与调度；
- 读取和同步开发状态；
- 为 Worker 定义目标、边界、证据与停止条件；
- 选择 `READ_ONLY` / `PATCH_WORKTREE` / `INTEGRATION` 执行模式；
- 管理 Patch Worktree 池与唯一 Integration Tree；
- blocker 汇总、去重与分类；
- batch repair 与集中 build/test 组织；
- 生成 Gate/Architect packet；
- 判断何时满足 Sol Max 触发条件。

不得自行：
- 创造/修改 frozen architecture；
- 弱化 invariant；
- 改 authority / migration / schema / recovery / security / protocol 语义；
- 代替 Luna High 做独立 gate。

### Luna Max / Worker
负责：
- Scout、代码调查、实现、repair、测试实现、fixture、canary、日志与证据分析。

Worker MUST：
- 只向 Coordinator 汇报；
- 在冻结边界内自主决定具体调查/实现方法；
- 返回 findings、patch/commit、tests、风险、假设和完整 blocker set。

Worker MUST NOT：
- 直接调用、请求或向 Sol Max 汇报；
- 自行改变 Stage Contract / frozen invariant；
- 在普通 Patch Worktree 中执行正常 build/test/canary。

### Sol Max / Architect
只负责：
- 新架构或重大架构裁决；
- frozen invariant 决策；
- 架构级 blocker 仲裁；
- 当前阶段架构闭合；
- **下一阶段目标与 Stage Contract 的确立**。

### Luna High / Independent Gate
只负责最终 Integration Candidate 的独立 whole-candidate gate。
不得参与 candidate 实现。
输出：
- `PASS`
- `BLOCKED_IMPLEMENTATION`
- `BLOCKED_ARCHITECTURE`

## 4. Worker 委派原则

Coordinator 给 Worker 的任务必须是：

> **高约束目标，低约束实现。**

MUST 明确：
- Goal；
- relevant context；
- frozen constraints；
- execution mode；
- allowed modification scope；
- required outputs/evidence；
- blocker policy；
- build policy；
- stop conditions。

除非 Sol Max 已冻结具体做法，否则 Coordinator SHOULD NOT 把实现步骤规定过死。

标准模板：
`docs/governance/templates/WORKER_TASK_PACKET.md`

## 5. Blocker batching

任何 Worker / Tester / Reviewer 发现 blocker 时：

1. 记录 blocker 与证据；
2. 在安全且仍有价值的范围内继续完成本轮调查；
3. 一次性向 Coordinator 返回 blocker set；
4. 不得“发现一个 blocker 就直接升级 Sol Max”。

Coordinator MUST 先汇总、去重、做 root-cause/dependency 分类，再：
- implementation/evidence blockers → 批量 repair；
- architecture blockers → 合并为一个 Architect Packet。

Luna High 也 SHOULD 尽量完成 whole-candidate 审查后一次返回完整 blocker set。

## 6. Parallel Workspace Policy

Worktree 是**代码隔离工具**，不是默认构建环境。

### READ_ONLY
适用于 Scout / review / evidence / root-cause。
直接共享仓库只读视图，不需要 worktree。

### PATCH_WORKTREE
用于 Luna Max 并行写互不冲突的代码。

规则：
- 最多 **3 个 active Patch Worktree**；
- Coordinator 负责分配、登记、回收；
- 使用确定性命名：`<stage>-w<n>-<short-task>`；
- SHOULD 放在仓库外固定 worktree 根目录；
- MUST NOT 进行普通 `cargo build/test`、Tauri build、real canary；
- 完成后导出 patch/local commit，集成或放弃后立即 remove/prune；
- 不得长期积累 `target/` 等构建产物。

### INTEGRATION
唯一真实集成工作树。负责：
- 批量应用/合并 Worker patch；
- candidate commit；
- 正常 compile/test；
- broader/full suite；
- real canary；
- Luna High gate 对应 exact SHA。

### ISOLATED_BUILD_WORKTREE
仅在互斥方案必须实际隔离构建验证时，由 Coordinator 明确批准。
必须临时、独立 target；可复用安全的编译器缓存，但不得与 Integration Tree 并发共享同一 `target/`。

## 7. 集中构建

Coordinator MUST 指定单一 **Integration / Build Owner**（通常为 Luna Max）：

`parallel investigation/edit -> patch batch -> integration -> focused build/test -> broader suite -> real canary`

普通 Patch Worktree 不编译。

Build Owner 必须指定为 Luna Max；Coordinator 不默认接替实现/构建职责。按实际并发槽拆任务，四槽包含 Coordinator，最多三个并行 Luna；共享文件/接口只有一个写 owner。执行分层、census coverage、attempt ledger 与缓存边界见执行效率规则。

除非技术上明确必要或用户要求：

> **MUST NOT run `cargo clean` or equivalent cache-clearing operations.**

## 8. Sol Max 触发条件

只有以下类型事件才升级 Architect：

- 需要新的 Stage Contract / 下一阶段确立；
- 当前阶段需要架构闭合；
- 需要新建或改变 architecture / frozen invariant；
- authority / grant/revoke / migration / schema / recovery / security / trust / identity / frozen protocol 发生语义问题；
- 多个 blocker 汇总后确认根因是架构冲突；
- Luna High 返回 `BLOCKED_ARCHITECTURE`；
- 用户改变 frozen requirement；
- 高可信证据证明现有 architecture contract 本身不成立。

普通 compile/test/fixture/evidence/patch conflict/repair 问题 MUST NOT 升级 Sol Max。

文档不限制 Sol Max 调用次数；只限制职责和触发条件。

## 9. 禁止进度轮询

Coordinator 不应频繁轮询 Worker/Luna 状态。
Sol Max MUST NOT 做：
- Worker progress tracking；
- Luna progress tracking；
- worktree 日常管理；
- repair supervision；
- 普通 blocker triage；
- 常规编译/测试分析。

结果完成后再汇总处理。

任务下发与完成后向用户回报；执行期被动等待保持会话。Coordinator 默认 90 分钟无结果事件后做一次异常检查，不做持续状态轮询；watchdog 不改变正式命令 timeout。Sol Max 只在架构触发或最终 closure 介入。

## 10. Gate 与 Git

- Gate MUST 绑定 **Integration Tree exact candidate SHA**。
- Patch Worktree 的 branch/commit 不是最终 Gate 对象。
- Repair 后产生新 candidate，旧 PASS 不自动继承。
- Required real canary 不可被 mock/compile/fixture PASS 替代。
- Security-sensitive work MUST 有 negative evidence。
- Evidence missing = `BLOCKED`。
- Dirty Integration Tree 不可 final freeze。
- 未经用户明确要求，MUST NOT push remote。
- 默认允许本地 commit。

## 11. 阶段闭合与下一阶段

Candidate local evidence 完整后：

`Coordinator -> Luna High`

结果：

- `BLOCKED_IMPLEMENTATION` → Coordinator 汇总并让 Luna Max 批量 repair → integrate → new candidate → re-gate
- `BLOCKED_ARCHITECTURE` → Coordinator 汇总 → Sol Max
- `PASS` → Coordinator 确认临时 Patch Worktree 已集成/清理，生成 Stage Closure Packet → Sol Max 做架构闭合；只有用户允许继续时才确立下一 Stage Contract。当前 D32 闭合、必要空间清理后停止，不进入 D33。

## 12. 完成定义

不得仅因代码写完或编译成功宣称阶段完成。

至少要求：
- implementation done；
- required tests pass；
- required canary pass；
- required negative evidence established；
- exact Integration Candidate SHA recorded；
- required Luna High gate completed；
- unresolved architecture blocker = 0；
- 临时 Patch Worktree 已集成或清理；
- Sol Max 已完成需要的阶段架构闭合；仅用户允许继续时确立下一阶段。D32 完成和必要清理后停止，不进入 D33。
