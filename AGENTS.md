# AGENTS.md — 虚拟生命项目 Codex 根治理入口

**Protocol:** v1.1  
**Scope:** 仓库根目录及全部子目录。  
**Full protocol:** `docs/governance/CODEX_DEVELOPMENT_PROTOCOL.md`

## 1. 当前模型映射

本项目当前模型信号由用户配置为 GPT-6 系列：

- **Coordinator:** Sol Medium / GPT-6
- **Architect:** Sol Max / GPT-6
- **Codex Worker:** Luna Max / GPT-6
- **Independent Gate:** Luna High / GPT-6

角色定义优先于未来具体模型名；若模型名称变化，保持职责不变，除非用户明确更新本文件。

核心原则：

> **Sol Medium 协调；Luna Max 执行；Sol Max 定架构与阶段；Luna High 独立门禁。**

## 2. 每次开发开始 MUST

Coordinator MUST：

1. 读取 Git branch / HEAD / working tree；
2. 读取：
   - `docs/governance/PROJECT_SOURCE_OF_TRUTH.md`
   - `docs/governance/CURRENT_DEVELOPMENT_STATE.md`
   - `docs/governance/FROZEN_INVARIANTS.md`
   - `docs/governance/ARCHITECTURE_DECISIONS.md`
3. 自动发现并核验当前开发总文档、阶段报告和最新 exact-SHA 证据；
4. 确定 `CURRENT_STAGE`；
5. 判断当前是否已有有效 Stage Contract；
6. 将执行工作分配给 Luna Max worker；
7. YELLOW/RED、架构争议、门禁或阶段切换时读取完整协议。

`CURRENT_DEVELOPMENT_STATE.md` 只是缓存，不得覆盖 Git 与已验证证据。

## 3. 角色边界

### Sol Medium / Coordinator
负责：
- 日常任务拆分与调度；
- 读取和同步开发状态；
- blocker 汇总与分类；
- batch repair 组织；
- 构建/测试协调；
- 生成 Gate/Architect packet；
- 决定何时满足 Sol Max 触发条件。

不得自行：
- 创造/修改 frozen architecture；
- 弱化 invariant；
- 改 authority / migration / schema / recovery / security / protocol 语义；
- 代替 Luna High 做独立 gate。

### Luna Max / Worker
负责：
- Scout、代码调查、实现、repair、测试实现、fixture、canary、日志与证据分析。

MUST report only to Coordinator。  
MUST NOT 直接调用、请求或向 Sol Max 汇报。

### Sol Max / Architect
只负责：
- 新架构或重大架构裁决；
- frozen invariant 决策；
- 架构级 blocker 仲裁；
- 当前阶段架构闭合；
- **下一阶段目标与 Stage Contract 的确立**。

### Luna High / Independent Gate
只负责独立 whole-candidate gate。  
不得参与 candidate 实现。  
输出：
- `PASS`
- `BLOCKED_IMPLEMENTATION`
- `BLOCKED_ARCHITECTURE`

## 4. Blocker batching

任何 worker / tester / reviewer 发现 blocker 时：

1. 记录 blocker 与证据；
2. 在安全且仍有价值的范围内继续完成本轮调查；
3. 一次性向 Coordinator 返回 blocker set；
4. 不得“发现一个 blocker 就直接升级 Sol Max”。

Coordinator MUST 先汇总、去重、做 root-cause/dependency 分类，再：
- implementation/evidence blockers → 批量 repair；
- architecture blockers → 合并为一个 Architect Packet。

Luna High 也 SHOULD 尽量完成 whole-candidate 审查后一次返回完整 blocker set；仅当继续检查无意义或可能产生危险副作用时可提前终止。

## 5. 禁止 worktree

除非用户明确要求：

> **MUST NOT create or use git worktrees.**

默认使用现有 repository working tree，以复用现有编译缓存。

只读 worker 可并行。  
写 worker 默认串行；只有修改范围完全不重叠时才允许受控并行。

## 6. 集中构建

Coordinator MUST 指定单一 Build Owner（通常为 Root 或 Tester）：

- worker 先完成一批修改；
- 再集中 focused build/test；
- 必要时 broader/full suite；
- 复用现有 `target/`、incremental cache 和已编译依赖。

除非技术上明确必要或用户要求：

> **MUST NOT run `cargo clean` or equivalent cache-clearing operations.**

## 7. Sol Max 触发条件

只有以下类型事件才升级 Architect：

- 需要新的 Stage Contract / 下一阶段确立；
- 当前阶段需要架构闭合；
- 需要新建或改变 architecture / frozen invariant；
- authority / grant/revoke / migration / schema / recovery / security / trust / identity / frozen protocol 发生语义问题；
- 多个 blocker 汇总后确认根因是架构冲突；
- Luna High 返回 `BLOCKED_ARCHITECTURE`；
- 用户改变 frozen requirement；
- 高可信证据证明现有 architecture contract 本身不成立。

普通 compile/test/fixture/evidence/repair 问题 MUST NOT 升级 Sol Max。

文档不限制 Sol Max 调用次数；只限制其职责和触发条件。

## 8. 禁止进度轮询

Coordinator 不应频繁轮询 worker/Luna 状态。  
Sol Max MUST NOT 做：
- worker progress tracking；
- Luna progress tracking；
- repair supervision；
- 普通 blocker triage；
- 常规编译/测试分析。

结果完成后再汇总处理。

## 9. Gate 与 Git

- Gate MUST 绑定 exact candidate SHA。
- Repair 后产生新 candidate，旧 PASS 不自动继承。
- Required real canary 不可被 mock/compile/fixture PASS 替代。
- Security-sensitive work MUST 有 negative evidence。
- Evidence missing = `BLOCKED`。
- Dirty tree 不可 final freeze。
- 未经用户明确要求，MUST NOT push remote。
- 默认允许本地 commit；不得创建 worktree。

## 10. 阶段闭合与下一阶段

Candidate local evidence 完整后：

`Coordinator -> Luna High`

结果：

- `BLOCKED_IMPLEMENTATION` → Coordinator 汇总并让 Luna Max 批量 repair → new candidate → re-gate
- `BLOCKED_ARCHITECTURE` → Coordinator 汇总 → Sol Max
- `PASS` → Coordinator 生成 Stage Closure Packet → Sol Max 做架构闭合并确立下一 Stage Contract

Sol Max 的阶段输出回到 Coordinator 后，进入下一阶段执行。

## 11. 完成定义

不得仅因代码写完或编译成功宣称阶段完成。

至少要求：
- implementation done；
- required tests pass；
- required canary pass；
- required negative evidence established；
- exact candidate SHA recorded；
- required Luna High gate completed；
- unresolved architecture blocker = 0；
- Sol Max 已完成需要的阶段架构闭合/下一阶段确立。
