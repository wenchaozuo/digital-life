# 虚拟生命项目：Codex 分层开发、模型路由与 HIGH Gate 强制协议

**文件名建议：** `CODEX_DEVELOPMENT_PROTOCOL.md`  
**协议版本：** 1.0  
**状态：** FROZEN GOVERNANCE BASELINE  
**适用范围：** 虚拟生命项目后续全部开发阶段，包括但不限于 Dxx、Hxx、Rx、迁移、恢复、Host/Vita 权限、Capability、文件系统、SQLite、Toolchain、Workspace、Identity、协议、测试、真实 canary 与门禁。  
**默认执行者：** Codex Root Agent + Codex Subagents  
**高风险架构权威：** GPT-5.6 Sol（High；在可用时对最高风险冻结可使用 Extra High）  
**独立门禁权威：** GPT-5.6 Luna（最高可用推理强度）  

---

## 0. 协议目的

本协议用于将虚拟生命项目后续开发默认交给 Codex 执行，同时：

1. 最大化使用 Codex 子代理承担高频、可并行、上下文消耗大的工程工作；
2. 将昂贵推理额度集中到真正影响架构正确性、权限边界、安全性、持久化一致性、恢复一致性和最终冻结的节点；
3. 保证 Codex **不能通过降低标准、弱化 invariant、扩大权限、修改冻结架构或跳过真实证据来“完成任务”**；
4. 保证 GPT-5.6 Sol 与 GPT-5.6 Luna 的职责严格分离：
   - **Sol：决定“允许怎样设计”。**
   - **Luna：独立判断“candidate 是否真的满足已冻结要求”。**
5. 保证所有 HIGH 风险里程碑都可以基于 exact SHA、可复现测试、真实 canary 和 negative evidence 进行独立复审。

本协议不是建议。除非用户明确在当前任务中覆盖某一条规则，否则 Codex MUST 按本协议执行。

---

# 1. 规范性术语

本文使用以下规范术语：

- **MUST**：必须执行，不得省略。
- **MUST NOT**：禁止执行。
- **SHOULD**：通常必须执行；仅在存在明确理由时可偏离，并必须记录理由。
- **SHOULD NOT**：通常禁止；如偏离必须记录理由。
- **MAY**：允许，但不是必需。
- **BLOCKED**：当前 candidate 不得冻结、不得宣称完成、不得升级为最终基线。
- **PASS**：仅代表当前定义的 gate 已被满足；不自动代表整个 milestone 最终冻结。
- **FROZEN**：经规定的最终冻结流程批准，成为后续开发约束。
- **INVARIANT**：不得被普通实现修改或弱化的系统不变量。
- **REAL CANARY**：在真实目标执行路径、真实 Host/OS/SQLite/文件系统/工具链语义下运行的验证，不等价于 mock、stub、纯内存模拟或仅单元测试。
- **NEGATIVE EVIDENCE**：证明禁止行为“没有发生”的证据，例如 mutation syscall = 0、revoke 后自动重试 = 0、production registry = 0。
- **EXACT CANDIDATE**：被门禁审查的唯一、精确 Git commit SHA。
- **ARCHITECTURE ESCALATION**：Codex 无权自行裁决，必须停止相关实现并提交给 Sol 的架构升级。

---

# 2. 总体控制层级

后续开发必须遵循以下权威顺序：

1. **用户当前明确指令**
2. **已冻结项目基线 / Frozen Invariants / Frozen Architecture**
3. **本协议**
4. **当前阶段设计文档与任务要求**
5. **Codex 自主工程判断**

Codex MUST NOT 使用较低层级的判断覆盖较高层级约束。

如果两个已冻结要求之间发生真实冲突：

- Codex MUST 停止相关实现；
- MUST 生成 `ARCHITECTURE_ESCALATION_PACKET`；
- MUST 标记为 `SOL_REQUIRED`；
- MUST NOT 自行选择“更方便实现”的一方。

---

# 3. 总体角色分工

## 3.1 Codex Root Agent

Codex Root Agent 是默认项目执行编排器。

Root Agent MUST 负责：

- 读取任务与当前冻结基线；
- 进行风险分类；
- 决定是否需要 Sol 前置架构裁决；
- 调度子代理；
- 控制并行度；
- 合并实现；
- 维护 Git 状态；
- 组织测试；
- 组织 real canary；
- 组织 negative evidence；
- 生成 candidate；
- 生成门禁包；
- 根据本协议判断下一步流转；
- 在需要时停止，而不是越权裁决。

Root Agent MUST NOT：

- 自行弱化 invariant；
- 自行改变冻结架构；
- 自行宣布 HIGH milestone FROZEN；
- 用更多子代理数量替代明确的任务边界；
- 在 gate 失败后通过修改测试标准来获得 PASS。

---

## 3.2 Codex Subagents

默认允许以下角色：

1. `SCOUT`
2. `IMPLEMENTER`
3. `TESTER`
4. `EVIDENCE`
5. `RED_TEAM_REVIEWER`

子代理不是独立架构权威。

所有子代理 MUST 服从 Root Agent 给出的：

- task scope；
- frozen invariants；
- allowed files；
- forbidden changes；
- expected evidence；
- required tests；
- stop conditions。

---

## 3.3 GPT-5.6 Sol

Sol 是高风险架构裁决与最终冻结权威。

Sol 的职责：

- RED 风险架构设计或架构复审；
- authority / trust boundary / capability / revoke / recovery / migration / persistence 等高风险决策；
- 解决冻结要求之间的冲突；
- 判断是否允许改变 frozen contract；
- 对真正 HIGH milestone 的最终 exact candidate 执行最终冻结裁决。

Sol SHOULD NOT 被用于：

- 普通代码搜索；
- 常规实现；
- 格式修复；
- 普通测试日志整理；
- 简单测试失败；
- 已冻结设计下的常规 repair；
- 普通 diff 初审。

---

## 3.4 GPT-5.6 Luna

Luna 是独立 HIGH Gate / Red-Team 审核权威。

Luna 的职责：

- 独立审查 exact candidate；
- 尝试证明实现未满足 frozen requirements；
- 审查 test matrix 是否充分；
- 审查 real canary 是否真实；
- 审查 negative evidence 是否能证明“未发生禁止行为”；
- 输出严格 `PASS` 或 `BLOCKED`；
- 对 blocker 给出最小、可验证的失败原因。

Luna MUST NOT 被默认当作架构主设计者。

Luna SHOULD 在不知道实现过程争论细节的情况下，根据：

- 原始 requirement；
- frozen invariants；
- exact SHA；
- diff；
- test matrix；
- canary；
- negative evidence；

进行相对独立的审核，以降低 confirmation bias。

---

# 4. 模型路由原则

默认工作负载目标：

| 工作类型 | 默认执行者 |
|---|---|
| 仓库搜索、调用链定位 | Codex Scout |
| 普通实现 | Codex Implementer |
| 单元/集成/回归测试 | Codex Tester |
| 日志与证据整理 | Codex Evidence |
| 低成本红队审查 | Codex Red-Team Reviewer |
| 多模块工程整合 | Codex Root |
| 高风险架构 | Sol |
| 独立 HIGH Gate | Luna |
| HIGH milestone 最终冻结 | Sol |

目标不是严格按 token 计费，而是让：

- **约 80%～90% 的工程活动留在 Codex 内部；**
- Sol/Luna 只介入高价值决策点。

MUST NOT 因为“强模型更聪明”而让 Sol/Luna 承担大量机械工程工作。

---

# 5. 风险分级

每个任务开始前，Root Agent MUST 将任务分类为：

- GREEN
- YELLOW
- RED

如果无法确定，MUST 向更高风险等级升级。

---

## 5.1 GREEN

典型情况：

- 测试补充；
- fixture 补充；
- 文档；
- 非语义性重构；
- 内部 helper；
- 错误文案；
- logging；
- 已冻结 contract 内的局部 bugfix；
- 不触碰安全/权限/持久化/恢复语义的优化。

默认流程：

`Codex -> local tests -> Codex Reviewer -> PASS`

GREEN 默认不调用 Sol/Luna。

如果开发过程中触碰 RED 条件，MUST 立即升级风险等级。

---

## 5.2 YELLOW

典型情况：

- 多模块实现；
- 新 execution path；
- 状态机局部扩展；
- 新 canary；
- recovery 内部实现，但明确不改变 contract；
- 新缓存/投影/调度机制；
- 并发实现细节，但不改变已有并发保证；
- 较大 refactor；
- 新的失败处理路径。

默认流程：

`Codex -> Subagents -> Tests -> Evidence -> Codex Red Team -> Luna High Gate`

YELLOW 通常不需要 Sol 前置设计。

如果 Luna 或 Codex 发现需要改变 frozen architecture，则升级为 RED。

---

## 5.3 RED

出现以下任意一项，任务 MUST 标记 RED：

- Host/Vita authority ownership；
- trust boundary；
- capability issuance；
- capability validation；
- grant / revoke semantics；
- privilege narrowing / escalation；
- persistent schema；
- migration；
- identity continuity；
- transaction atomicity；
- crash recovery；
- recovery journal；
- cancellation semantics；
- race / concurrency correctness；
- TOCTOU；
- handle-relative security；
- pathname reopen 安全边界；
- unsafe / native syscall 语义；
- SQLite authority；
- external protocol；
- IPC contract；
- frozen API；
- storage key；
- cross-process authority；
- workspace authority；
- source-of-truth ownership；
- toolchain authority；
- irreversible compatibility change；
- security-sensitive filesystem mutation；
- “必须弱化某个 invariant 才能继续”。

默认流程：

`Scout -> Sol Architecture -> Frozen Decision -> Codex Implementation -> Tests -> Real Canary -> Evidence -> Codex Red Team -> Luna High Gate -> repair loop if needed -> Sol Final Freeze if milestone`

---

# 6. SOL_REQUIRED 强制触发器

满足以下任意条件，Codex MUST 停止相关架构实现并输出 `ARCHITECTURE_ESCALATION_PACKET`：

1. 需要修改 frozen invariant；
2. 需要重新解释 frozen invariant；
3. 需要改变 authority ownership；
4. 需要改变 grant/revoke；
5. 需要新增/修改 migration；
6. 需要修改持久化 schema；
7. 需要改变 crash/recovery atomicity；
8. 需要改变 cancellation 语义；
9. 需要改变 security/trust boundary；
10. 需要改变 external/frozen protocol；
11. 需要放宽测试标准才能让实现通过；
12. 当前要求与冻结架构冲突；
13. 两个冻结要求互相冲突；
14. 实现只能依赖 undocumented privilege；
15. 实现需要引入新的 production authority registry；
16. 实现需要重新开放已封闭的 pathname-based mutation；
17. 实现需要绕过 Host-issued evidence；
18. 实现需要扩大 child process 对用户 profile / Host root / workspace 的暴露；
19. 实现需要改变身份连续性或持久凭据模型；
20. Luna 明确指出 blocker 是架构冲突而非实现缺陷。

此时：

- MUST 标记 `SOL_REQUIRED`;
- MUST NOT 继续“先写出来再看”；
- MAY 继续进行纯只读调查；
- MUST NOT 提交改变架构语义的 candidate。

---

# 7. 不得升级 Sol 的常规问题

以下问题默认 MUST 由 Codex 修复，不得自动消耗 Sol：

- 测试没跑全；
- fixture 漏覆盖；
- typo；
- compile error；
- borrow checker / type error；
- format；
- lint；
- 日志格式；
- candidate SHA 写错；
- evidence 不完整；
- mock 被误当 real canary；
- revoke test 没证明 mutation=0；
- crash fixture 没覆盖某分支；
- test assertion 太弱；
- regression；
- feature flag 配置错误；
- path/fixture setup 错误；
- 实现明显偏离已经冻结的设计；
- Luna 指出的实现级 blocker。

默认 repair：

`Luna BLOCKED -> Codex repair -> new exact candidate -> Luna re-gate`

只有 repair 必须修改冻结架构时才升级 Sol。

---

# 8. 子代理并发与额度纪律

## 8.1 默认并发上限

默认单任务最大建议：

- 1 × Scout
- 1～2 × Implementer
- 1 × Tester
- 1 × Evidence / Reviewer

通常不得超过 **5 个活跃角色**。

Root Agent MUST NOT 无理由启动大量代理“全面调查”。

---

## 8.2 实现并行规则

两个 Implementer SHOULD NOT 同时修改同一个核心生产文件。

如果必须修改：

- Root Agent MUST 明确分区；
- MUST 明确合并顺序；
- MUST 在合并后重新跑相关测试；
- MUST 重新执行 reviewer。

---

## 8.3 最小上下文原则

每个子代理只接收完成任务所需的最小上下文。

Implementer 输入 SHOULD 限制为：

- task；
- relevant frozen invariants；
- allowed files；
- forbidden changes；
- relevant symbols；
- required tests；
- expected output。

MUST NOT 默认把整个 D1～当前阶段历史复制给所有子代理。

需要历史时优先由 Scout 定位并摘要。

---

# 9. 子代理角色强约束

## 9.1 SCOUT

SCOUT MUST：

- 只读；
- 找出相关文件、symbol、调用链、现有测试；
- 标记 frozen boundary；
- 标记可能风险；
- 给出最小 change set；
- 不写生产代码。

输出：

```text
SCOUT REPORT

Task:
...

Relevant files:
- ...

Relevant symbols:
- ...

Frozen invariants touched:
- ...

Expected change set:
- ...

Potential hidden coupling:
- ...

Risk recommendation:
GREEN / YELLOW / RED
```

---

## 9.2 IMPLEMENTER

IMPLEMENTER MUST：

- 只实现分配范围；
- 不自行修改 frozen requirements；
- 不擅自扩大文件范围；
- 不为“方便”引入新的 authority；
- 不删除失败测试；
- 不将真实验证改成 mock；
- 报告所有偏离。

IMPLEMENTER 遇到越权条件 MUST 返回：

`STOPPED — ARCHITECTURE ESCALATION REQUIRED`

---

## 9.3 TESTER

TESTER MUST 与主实现逻辑尽量独立。

TESTER MUST：

- 验证 happy path；
- 验证 failure path；
- 验证 revoke；
- 验证 cancel；
- 验证 crash/restart（若适用）；
- 验证 stale evidence（若适用）；
- 验证 wrong authority；
- 验证 zero-mutation boundary；
- 验证回归。

TESTER MUST NOT：

- 为了让测试通过而修改生产语义；
- 删除或弱化现有安全测试；
- 把失败 case 改成 success case；
- 仅凭单元测试宣称 real canary PASS。

---

## 9.4 EVIDENCE

EVIDENCE Agent MUST 生成可审计报告。

MUST 记录：

- base；
- parent；
- candidate；
- branch；
- dirty/clean；
- focused tests；
- regression tests；
- full tests；
- ignored tests；
- real canary；
- negative evidence；
- known unverified items；
- forbidden changes count；
- production registry count（若适用）；
- mutation syscall count（若适用）；
- auto retry after revoke count（若适用）。

任何没有执行的项 MUST 写 `NOT RUN`，不得留空冒充通过。

---

## 9.5 RED_TEAM_REVIEWER

Reviewer 的任务不是证明实现正确，而是主动寻找 blocker。

至少检查：

- 是否使用了旧 snapshot；
- 是否存在 session-start snapshot reuse；
- 是否有 authority 泄漏；
- 是否在 revoke/cancel 后发生 mutation；
- 是否自动 retry；
- 是否存在 pathname reopen；
- 是否仅 mock；
- 是否存在 stale evidence；
- 是否有 hidden production registry；
- 是否新增了未批准 persistence；
- 是否改变 frozen contract；
- 是否有“测试通过但语义不成立”的情况。

输出 MUST 优先列 blocker，而不是赞扬实现。

---

# 10. Git 与 Exact SHA 纪律

HIGH/YELLOW gate 前 MUST 明确：

```text
Branch:
Base:
Parent:
Candidate:
Merge-base:
Working tree:
```

## 10.1 基本规则

- Gate MUST 针对 exact commit SHA。
- Gate 时工作区 SHOULD clean。
- 如果 dirty，MUST 标记 `DIRTY — NOT ELIGIBLE FOR FINAL FREEZE`。
- MUST NOT 使用“最新代码”“当前分支大概就是”作为 gate 对象。
- repair 后 MUST 产生新的 candidate SHA。
- 旧 candidate 的 PASS 不自动继承给新 candidate。
- rebase/cherry-pick/force rewrite 后，旧 gate 结果无效，除非 exact tree 被明确证明一致并经门禁接受。
- 最终冻结 MUST 记录 exact SHA。

---

# 11. Candidate 构建纪律

一个 candidate 只有满足以下条件才可进入独立 gate：

1. 目标实现完成；
2. 相关 focused tests PASS；
3. 相关 regression tests PASS；
4. 必要 full suite 已执行；
5. 必要 fixture 构建 PASS；
6. 必要 real canary 已执行；
7. negative evidence 已生成；
8. working tree clean；
9. exact candidate SHA 已记录；
10. known blockers = 0。

否则状态必须是：

`NOT READY FOR GATE`

---

# 12. 测试分层

每个非简单任务 SHOULD 至少包含：

1. focused unit/integration tests；
2. regression tests；
3. project-relevant broader suite；
4. real canary（YELLOW/RED 中按风险决定）；
5. negative evidence。

测试数量不是核心标准。

核心标准：

> 测试是否真正覆盖 frozen invariant。

---

# 13. Real Canary 规则

以下情况不能被 mock 替代：

- Host authority；
- real filesystem mutation；
- real revoke；
- real process boundary；
- real SQLite persistence；
- crash/restart；
- native handle-relative operation；
- toolchain execution；
- workspace visibility；
- OS-level cancellation；
- production-like identity binding。

如果 requirement 明确要求 real canary：

- mock PASS = **不能关闭 gate**
- fixture PASS = **不能替代 real canary**
- compile PASS = **不能替代 real canary**

无法执行 real canary 时必须：

`BLOCKED — REAL CANARY NOT ESTABLISHED`

除非 frozen requirement 明确允许 deferred canary。

---

# 14. Negative Evidence 规则

对安全/权限/恢复任务，仅证明“正确路径成功”不够。

必须按任务证明禁止行为没有发生。

典型指标：

```text
unauthorized mutation = 0
mutation after revoke = 0
mutation after cancel fence = 0
automatic retry after revoke = 0
production authority registry = 0
pathname reopen = 0
unexpected workspace exposure = 0
unexpected profile exposure = 0
journal written before expected check = 0
stale evidence accepted = 0
```

如某项不适用，写：

`N/A — reason`

不得省略。

---

# 15. Fail-Closed 原则

当证据不足时，默认结论必须是：

`BLOCKED`

不得使用：

- probably pass
- likely safe
- seems okay
- should be fine
- tests mostly pass

来关闭 HIGH gate。

**No evidence != PASS.**

---

# 16. Repair / Re-Gate 规则

Luna 或本地 gate BLOCKED 后：

1. Codex MUST 先完成 Blocker Census 与 Common-root clustering，再按共同根因建立 repair batch；
2. MUST 保持原 frozen architecture 不变；
3. MUST 生成新的 exact candidate；
4. MUST 重新跑所有受影响 focused tests；
5. MUST 重跑 blocker 对应 negative evidence；
6. SHOULD 重跑相关 broader regression；
7. MUST 重新进入 Luna gate（YELLOW/RED）。

如果 repair 触碰：

- architecture；
- invariant；
- authority；
- migration；
- security boundary；

则：

`REPAIR STOPPED — SOL_REQUIRED`

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

在启动昂贵 build 或 real canary 前，Evidence Agent MUST 出具一次聚合检查，至少确认：

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

---

# 17. HIGH Milestone 最终冻结

Luna PASS 不等于 HIGH milestone 自动 FROZEN。

真正 HIGH milestone 的最终流程：

```text
Codex candidate ready
    ↓
Codex Red Team PASS
    ↓
Luna High PASS
    ↓
Sol Final Whole-Candidate Review
    ↓
FROZEN / BLOCKED
```

Sol Final Freeze SHOULD 聚焦：

- exact candidate；
- frozen architecture compliance；
- unresolved blockers；
- cross-cutting regressions；
- authority/security/recovery consistency；
- final evidence completeness。

中间普通 R1/R2/R3 repair 不需要每次重新调用 Sol，只要 frozen architecture 未改变。

---

# 18. Sol 架构裁决输出规范

Sol 输出 SHOULD 形成可执行冻结决定：

```text
ARCHITECTURE DECISION

Decision ID:
...

Status:
APPROVED / BLOCKED / APPROVED WITH CONDITIONS

Frozen invariants:
1.
2.
3.

Allowed implementation space:
- ...

Forbidden implementation:
- ...

Required tests:
- ...

Required real canary:
- ...

Required negative evidence:
- ...

Compatibility constraints:
- ...

Escalation conditions:
- ...
```

一旦标记 `APPROVED` 并进入当前开发阶段，该决定成为 Codex 的实现边界。

Codex MUST NOT 自行重新解释。

---

# 19. Luna Gate 输入规范

给 Luna 的输入 SHOULD 尽量避免开发过程噪声。

标准包：

```text
LUNA HIGH GATE PACKET

Task / Requirement:
...

Frozen invariants:
1.
2.

Base:
...

Parent:
...

Candidate:
...

Diff scope:
...

Focused tests:
...

Regression:
...

Full suite:
...

Real canary:
...

Negative evidence:
...

Known limitations:
...

Requested verdict:
PASS or BLOCKED only.
```

Luna SHOULD 独立攻击 candidate，而非复述 Codex 结论。

---

# 20. Luna Gate 输出规范

允许两种顶层结果：

## PASS

```text
PASS

Candidate:
<exact SHA>

Scope:
...

Evidence accepted:
- ...

Residual non-blocking risks:
- ...
```

## BLOCKED

```text
BLOCKED

Candidate:
<exact SHA>

B1:
Requirement:
Evidence:
Failure:
Required closure proof:

B2:
...
```

不得使用模糊的“基本通过”。

---

# 21. Codex Implementation Report 标准模板

每个重要 candidate MUST 能输出：

```text
# IMPLEMENTATION REPORT

Task:
...

Risk:
GREEN / YELLOW / RED

Branch:
...

Base:
...

Parent:
...

Candidate:
...

## 1. FROZEN INVARIANTS

- ...

## 2. IMPLEMENTED

- ...

## 3. FILES CHANGED

- ...

## 4. FOCUSED TESTS

Command:
Result:

## 5. REGRESSION TESTS

Command:
Result:

## 6. FULL / BROADER SUITE

Command:
Result:

## 7. REAL CANARY

Scenario:
Expected:
Observed:
Result:

## 8. NEGATIVE EVIDENCE

unauthorized mutation = ...
mutation after revoke = ...
automatic retry = ...
production registry = ...
...

## 9. COMPATIBILITY

Schema changed = YES/NO
Migration added = YES/NO
Protocol changed = YES/NO
Frozen API changed = YES/NO
Authority model changed = YES/NO

## 10. KNOWN LIMITATIONS

- ...

## 11. GATE READINESS

READY / NOT READY

Reason:
...
```

---

# 22. Architecture Escalation Packet 模板

Codex 触发 `SOL_REQUIRED` 时 MUST 输出：

```text
# ARCHITECTURE ESCALATION PACKET

Task:
...

Current risk:
RED

Trigger:
<which SOL_REQUIRED rule>

Frozen baseline:
...

Relevant invariants:
1.
2.

Observed conflict:
...

Why ordinary implementation cannot safely proceed:
...

Relevant files/symbols:
- ...

Evidence gathered:
- ...

Options:

A:
Pros:
Cons:
Security impact:
Compatibility impact:

B:
...

Codex recommendation:
<optional, non-authoritative>

Decision required from Sol:
...
```

Codex 在 Sol 裁决前不得实现改变架构语义的方案。

---

# 23. 上下文与 Token 节省规则

为了减少高级额度与总体 token 消耗：

1. MUST 优先让 Scout 做仓库定位；
2. MUST 使用摘要向 Implementer 传递上下文；
3. MUST NOT 让所有子代理重复扫描整个 repo；
4. MUST NOT 将完整历史日志发送给 Sol；
5. MUST 将 Sol 输入压缩为 Architecture Packet；
6. MUST 将 Luna 输入压缩为 Gate Packet；
7. SHOULD 复用已冻结 invariant 文档，而不是每轮重新解释；
8. SHOULD 保存 decision log；
9. SHOULD 保存 gate history；
10. MUST 避免多个子代理重复做相同搜索；
11. SHOULD 在同一 candidate 上复用可靠测试结果，但 repair 影响范围内必须重跑；
12. MUST NOT 以节省 token 为理由跳过 required canary / evidence。

---

# 24. 建议的项目治理文件

如果仓库允许，建议维护：

```text
/AGENTS.md
/docs/governance/CODEX_DEVELOPMENT_PROTOCOL.md
/docs/governance/FROZEN_INVARIANTS.md
/docs/governance/ARCHITECTURE_DECISIONS.md
/docs/governance/GATE_HISTORY.md
```

如果已有等价文件，SHOULD 复用现有结构，不强制重构仓库。

本协议可作为主文件。

`AGENTS.md` 可以仅包含：

```text
All development MUST comply with:
docs/governance/CODEX_DEVELOPMENT_PROTOCOL.md

If any conflict exists, stop and escalate according to the protocol.
```

---

# 25. Codex 禁止自行裁决清单

Codex MUST NOT independently：

1. weaken a frozen invariant；
2. redefine authority ownership；
3. alter grant/revoke semantics；
4. modify persistent schema；
5. introduce/alter migration；
6. change recovery atomicity；
7. change security/trust boundary；
8. change external/frozen protocol；
9. redefine cancellation semantics；
10. reopen a previously closed security path；
11. replace required real canary with mock；
12. delete failing tests to obtain PASS；
13. change expected result to match implementation；
14. hide known blocker；
15. claim unrun tests as PASS；
16. claim dirty tree as frozen candidate；
17. declare HIGH milestone FROZEN；
18. treat Luna PASS as automatic Sol freeze；
19. treat old candidate gate as valid for a new SHA；
20. bypass a `SOL_REQUIRED` trigger。

违反任意一项，当前 candidate MUST 被视为：

`INVALID FOR FREEZE`

---

# 26. Codex 任务启动流程

每次收到“继续开发”“执行下一阶段”“实现 Dxx-X”之类指令时，Codex MUST：

### Step 1 — Baseline

读取：

- 当前 branch；
- HEAD；
- git status；
- frozen baseline；
- relevant architecture decisions；
- current task requirement。

### Step 2 — Risk

输出内部或报告化判断：

```text
Risk = GREEN / YELLOW / RED
Reason = ...
SOL_REQUIRED = YES/NO
LUNA_GATE_REQUIRED = YES/NO
```

### Step 3 — Scout

非极小任务 SHOULD 先执行 Scout。

### Step 3A — Batch diagnosis

如果任务属于阶段级、多门禁、昂贵 build/real canary 或连续 repair，MUST 按第 16.1 节先完成 Blocker Census 与 Common-root clustering，并在 Batch Repair 后完成 Full affected matrix；未完成前不得直接进入昂贵 gate。

### Step 4 — Architecture

如果 RED / SOL_REQUIRED：

- 停止高风险实现；
- 生成 packet；
- 交 Sol。

### Step 5 — Implement

由 1～2 Implementer 执行明确切片。

### Step 6 — Test

独立 Tester 执行 required matrix。

### Step 7 — Evidence

Evidence Agent 生成证据。

### Step 8 — Cheap Red Team

Codex Reviewer 主动寻找 blocker。

### Step 9 — Gate

- GREEN：本地 gate 即可；
- YELLOW：Luna；
- RED：Luna；
- HIGH milestone final：Luna PASS 后 Sol Final。

---

# 27. 标准状态机

```text
                           ┌───────────────┐
                           │     TASK      │
                           └───────┬───────┘
                                   │
                                   ▼
                           ┌───────────────┐
                           │ RISK CLASSIFY │
                           └───┬────┬──────┘
                               │    │
                    GREEN ─────┘    └──── YELLOW
                               │
                               │ RED
                               ▼
                        ┌─────────────┐
                        │ SOL DESIGN  │
                        └──────┬──────┘
                               │
                               ▼
                         ┌──────────┐
                         │  SCOUT   │
                         └────┬─────┘
                              │
                              ▼
                      ┌───────────────┐
                      │ IMPLEMENTERS  │
                      └───────┬───────┘
                              │
                              ▼
                         ┌─────────┐
                         │ TESTER  │
                         └────┬────┘
                              │
                              ▼
                        ┌──────────┐
                        │ EVIDENCE │
                        └────┬─────┘
                             │
                             ▼
                     ┌────────────────┐
                     │ CODEX RED TEAM │
                     └───────┬────────┘
                             │
              ┌──────────────┴─────────────┐
              │                            │
           GREEN                      YELLOW / RED
              │                            │
              ▼                            ▼
            DONE                     ┌───────────┐
                                     │ LUNA GATE │
                                     └─────┬─────┘
                                           │
                               ┌───────────┴────────────┐
                               │                        │
                              PASS                   BLOCKED
                               │                        │
                               │                  implementation?
                               │                    │         │
                               │                   YES       NO
                               │                    │         │
                               │                  CODEX      SOL
                               │                    │         │
                               └────────────────────┴─────────┘
                                           │
                                           ▼
                                    HIGH MILESTONE?
                                      │         │
                                     NO        YES
                                      │         │
                                     DONE   SOL FINAL
                                                │
                                         PASS / BLOCKED
```

---

# 28. “证据优先于叙述”原则

门禁判断中的证据优先级：

1. exact SHA 上可复现的真实执行；
2. real canary；
3. deterministic test；
4. syscall / filesystem / SQLite / process evidence；
5. code inspection；
6. developer explanation。

口头解释不能覆盖失败的真实证据。

如果代码“看起来正确”但 canary 失败：

`BLOCKED`

如果 test PASS 但真实 authority 路径未验证：

`BLOCKED`

---

# 29. Compatibility 默认策略

除非架构裁决明确批准，否则 Codex MUST 默认保持：

- 已冻结后端协议兼容；
- 已冻结 persistence 兼容；
- 已冻结 storage key 兼容；
- 已冻结状态结构兼容；
- 已冻结 capability semantics 兼容；
- 已冻结 Host/Vita 边界兼容；
- 已冻结 recovery contract 兼容；
- 已冻结测试门禁不降低。

“为了实现简单”不是破坏兼容性的充分理由。

---

# 30. 未知情况处理

如果出现本协议未覆盖的新型高风险问题：

- 默认归类为 YELLOW；
- 若涉及 authority / persistence / security / irreversible compatibility，则升级 RED；
- 无法判断是否安全时，FAIL CLOSED；
- Codex MUST NOT 以“协议没有禁止”为依据自行扩大权限。

---

# 31. 用户可覆盖规则

用户可以在单次任务中明确覆盖本协议某条规则。

覆盖必须：

- 明确；
- 可识别具体条款；
- 不得由 Codex 自己推断。

例如：

```text
For D33-B only, Sol final freeze is deferred by user instruction.
```

Codex MUST 在报告中记录 override。

普通的：

“继续”
“做完它”
“尽快”
“直接实现”

不构成对安全/门禁规则的覆盖。

---

# 32. 默认任务完成标准

Codex 不得仅因“代码写完”宣称完成。

完成至少要求：

```text
implementation = done
required tests = pass
required canary = pass
required negative evidence = established
candidate = exact SHA
working tree = clean
required independent gate = pass
architecture escalation = none unresolved
```

如果为 HIGH milestone，还必须：

```text
Sol final freeze = PASS
```

---

# 33. 默认开发指令

用户后续可以直接对 Codex 使用：

> 严格按照 `CODEX_DEVELOPMENT_PROTOCOL.md` 执行当前阶段开发。  
> 先读取当前 frozen baseline、Git 状态和相关架构决定，自动进行 GREEN/YELLOW/RED 风险分类。  
> 充分使用 Codex 子代理执行 Scout、Implementation、Testing、Evidence 和 Red-Team，但必须遵守并发和最小上下文规则。  
> 遇到 `SOL_REQUIRED` 条件必须立即停止相关高风险实现并生成 `ARCHITECTURE_ESCALATION_PACKET`，不得自行裁决。  
> YELLOW/RED candidate 在本地证据完整后进入 Luna HIGH Gate。  
> Luna 的实现级 blocker 由 Codex repair 后重新 gate；只有架构冲突才升级 Sol。  
> HIGH milestone 只有在 Luna PASS 后，才允许进入 Sol Final Freeze。  
> 不得弱化 invariant、不得跳过 real canary、不得将 mock 视为真实证据、不得以 dirty tree 或非 exact SHA 宣称冻结。  
> 持续执行直到得到可验证的 PASS，或遇到协议规定必须由 Sol/用户裁决的 BLOCKED 状态。

---

# 34. 最终执行原则

Codex 后续开发必须长期遵守以下十条核心原则：

1. **Codex 负责做，Sol 负责定，Luna 负责审。**
2. **普通问题不消耗架构权威。**
3. **架构问题不得由实现代理越权解决。**
4. **子代理并行必须有边界，不以数量代替质量。**
5. **测试与实现尽量独立。**
6. **真实 canary 不能被 mock 替代。**
7. **安全任务必须提供 negative evidence。**
8. **任何 gate 都绑定 exact SHA。**
9. **证据不足时 FAIL CLOSED。**
10. **HIGH milestone 只有最终架构权威可以冻结。**

---

## 协议结束

只要本文件处于项目生效治理范围内，Codex 应将其视为后续开发的默认强制执行规则。

**默认原则：未明确授权的架构变更 = 禁止。未建立的证据 = 未通过。未完成的 HIGH Gate = 未冻结。**
