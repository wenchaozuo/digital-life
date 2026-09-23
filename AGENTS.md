# AGENTS.md — 虚拟生命项目 Codex 根治理入口

> **作用域：仓库根目录及其全部子目录。**
>
> 本文件是 Codex 每次进入仓库时应优先读取的短规则入口。
> 完整治理协议位于：`docs/governance/CODEX_DEVELOPMENT_PROTOCOL.md`

## 1. 强制角色分工

- **Codex**：默认工程执行者与编排器。
- **Codex Subagents**：承担 Scout / Implementer / Tester / Evidence / Red-Team。
- **GPT-5.6 Sol**：高风险架构权威与 HIGH milestone 最终冻结权威。
- **GPT-5.6 Luna（最高可用推理）**：独立 HIGH Gate / Red-Team 审核权威。

核心原则：

> **Codex 负责做；Sol 负责定；Luna 负责审。**

## 2. 每个任务开始前 MUST

1. 读取 Git 当前状态：
   - branch
   - HEAD
   - working tree
   - merge-base / base（如任务已指定）
2. 读取：
   - `docs/governance/FROZEN_INVARIANTS.md`
   - `docs/governance/ARCHITECTURE_DECISIONS.md`
   - `docs/governance/CURRENT_DEVELOPMENT_STATE.md`
3. 将任务分类：
   - `GREEN`
   - `YELLOW`
   - `RED`
4. 判断：
   - `SOL_REQUIRED = YES/NO`
   - `LUNA_GATE_REQUIRED = YES/NO`

无法确定风险等级时，向更高风险等级升级。

5. 对阶段级或包含多个门禁的任务，先执行批量诊断与修复流程：
   `Blocker Census -> Common-root clustering -> Batch Repair -> Full affected matrix -> Expensive build/real canary`
   - 先盘点当前阶段、相邻阶段、validator 与跨提交契约中的全部 blocker，再按共同根因归类；
   - 不得按 `gate fail -> fix one -> rerun expensive gate` 逐个试错；仅当安全或数据风险要求立即停止时例外，并记录停止原因。

## 3. Codex MUST NOT

Codex 不得自行：

1. 弱化 frozen invariant；
2. 修改 frozen architecture；
3. 改变 authority ownership；
4. 改变 grant/revoke semantics；
5. 修改 persistent schema；
6. 新增或修改 migration；
7. 改变 crash/recovery atomicity；
8. 改变 security / trust boundary；
9. 改变 external/frozen protocol；
10. 改变 identity continuity；
11. 用 mock 替代 required real canary；
12. 删除/弱化失败测试以获得 PASS；
13. 把未执行的测试写成 PASS；
14. 对 dirty working tree 宣称 final frozen；
15. 对非 exact SHA 做最终门禁；
16. 自行宣布 HIGH milestone FROZEN；
17. 绕过 `SOL_REQUIRED`；
18. 因 token/时间压力跳过 required evidence。

任何上述情况出现时：

`STOPPED — ARCHITECTURE ESCALATION REQUIRED`

并生成：
`docs/governance/templates/ARCHITECTURE_ESCALATION_PACKET.md`
对应格式的升级包。

## 4. 风险路由

### GREEN

默认：

`Codex -> Tests -> Codex Reviewer -> Done`

通常不调用 Sol / Luna。

### YELLOW

默认：

`Codex -> Subagents -> Tests -> Evidence -> Codex Red Team -> Luna High Gate`

### RED

默认：

`Scout -> Sol Architecture Decision -> Codex Implementation -> Tests -> Real Canary -> Evidence -> Codex Red Team -> Luna High Gate -> Sol Final Freeze（若为 HIGH milestone）`

## 5. 子代理默认预算

默认最多：

- 1 × Scout
- 1～2 × Implementer
- 1 × Tester
- 1 × Evidence / Red-Team

除非任务确实需要，不得无约束扩散子代理数量。

两个 Implementer SHOULD NOT 同时修改同一个核心生产文件。

## 6. 子代理最小上下文

不得默认让所有子代理读取完整项目历史。

每个子代理只接收：

- 当前 task；
- relevant frozen invariants；
- allowed files；
- forbidden changes；
- relevant symbols；
- required tests；
- expected output；
- stop conditions。

## 7. Gate 核心纪律

- Gate MUST 绑定 exact Git SHA。
- Repair 后 MUST 形成新的 candidate SHA。
- 旧 candidate 的 PASS 不自动继承。
- Required real canary 不得被 mock/fixture/compile PASS 替代。
- Security-sensitive work MUST 有 negative evidence。
- Evidence missing = `BLOCKED`。
- Dirty tree = `NOT ELIGIBLE FOR FINAL FREEZE`。
- 阶段级或多门禁任务 MUST 按 `Blocker Census -> Common-root clustering -> Batch Repair -> Full affected matrix -> Expensive build/real canary` 执行；不得逐个 blocker 触发昂贵 gate。
- 昂贵 build/real canary 前 MUST 完成一次聚合检查：governance 状态、exact SHA/clean、provenance schema/canonical paths、bundle hashes、provider/tool two-turn contract、mode matrix、cleanup/resource lifecycle。
- 每次 repair MUST 检查与相邻阶段及 validator 的跨提交契约；局部修复或单项测试通过不等于受影响链路已恢复。

## 8. Luna BLOCKED 后

实现级 blocker：

`Luna BLOCKED -> Codex Repair -> New Candidate -> Luna Re-Gate`

架构级 blocker：

`Luna BLOCKED -> SOL_REQUIRED -> Sol Arbitration`

不得把普通 compile/test/fixture/evidence 问题升级给 Sol。

## 9. HIGH milestone

HIGH milestone 只有以下流程全部完成才可冻结：

`Codex Ready -> Codex Red Team PASS -> Luna High PASS -> Sol Final Whole-Candidate PASS -> FROZEN`

Luna PASS ≠ 自动冻结。

## 10. 必读完整版的情况

出现以下任一情况 MUST 阅读：

`docs/governance/CODEX_DEVELOPMENT_PROTOCOL.md`

- YELLOW 或 RED；
- SOL_REQUIRED 可能触发；
- 准备 Luna gate；
- 准备 HIGH milestone freeze；
- 需要判断 real canary / negative evidence；
- 治理规则存在歧义；
- repair 可能触碰 frozen boundary。

## 11. 报告模板

使用：

- `docs/governance/templates/IMPLEMENTATION_REPORT.md`
- `docs/governance/templates/ARCHITECTURE_ESCALATION_PACKET.md`
- `docs/governance/templates/LUNA_HIGH_GATE_PACKET.md`
- `docs/governance/templates/SOL_ARCHITECTURE_DECISION.md`
- `docs/governance/templates/SOL_FINAL_FREEZE_REPORT.md`

## 12. 默认完成定义

不得仅因“代码写完/编译成功”宣称完成。

至少要求：

- implementation done；
- required tests pass；
- required canary pass；
- required negative evidence established；
- exact candidate SHA recorded；
- working tree clean；
- required independent gate pass；
- unresolved architecture escalation = 0。

若为 HIGH milestone，还必须：

`Sol Final Freeze = PASS`
