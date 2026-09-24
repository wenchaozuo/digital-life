# PROJECT_SOURCE_OF_TRUTH.md

本文件规定 Coordinator 如何自动发现真实开发状态并确定当前/下一阶段。

## 1. 不同问题使用不同权威来源

### 代码现实
以 Git actual state 和 exact execution evidence 为最高事实来源：

- branch / HEAD / parent / merge-base
- tracked diff
- exact candidate SHA
- actual test/canary output

开发报告不能覆盖与 Git 直接矛盾的代码现实。

### 规范性架构
以以下内容为权威：

1. 用户当前明确指令；
2. 已批准 `ARCHITECTURE_DECISIONS.md`；
3. `FROZEN_INVARIANTS.md`；
4. 当前有效 Stage Contract。

“代码现在这样写”不能反向修改 frozen architecture。

### 开发阶段与计划
按以下顺序判断：

1. Sol Max 最新有效 Stage Contract / Stage Closure decision；
2. 与 exact SHA 可交叉验证的最新开发总文档/阶段报告；
3. `CURRENT_DEVELOPMENT_STATE.md` 缓存；
4. 更早历史报告。

## 2. 启动时自动发现开发资料

Coordinator MUST 在仓库内搜索与以下语义相关的受版本控制文档：

- Baseline / Frozen
- 当前开发总文档 / development state
- Stage / Dxx / Hxx / Rx
- IMPLEMENTATION REPORT
- Gate / PASS / BLOCKED
- Architecture Decision
- exact candidate / base / parent

优先使用 `git ls-files`、仓库目录和文档内容发现，不依赖单纯文件修改时间。

## 3. 选择“最新开发文档”不得只看文件名日期

必须交叉验证：
- 文档声明的 Base/Candidate 是否能在 Git 中解析；
- 与当前 HEAD 的 ancestry 关系；
- 文档中的阶段结果是否有对应 commit/test/gate evidence；
- 是否被更新的 Stage Contract / Gate 覆盖。

无法验证的“最新”文档只可作为线索，不得直接成为 authoritative state。

## 4. CURRENT_DEVELOPMENT_STATE 是缓存

如果状态页与 Git/已验证文档冲突：

- 不得盲信状态页；
- Coordinator MUST 修正状态页；
- 在报告中简短记录冲突来源。

## 5. 当前阶段确定

Coordinator 应输出内部状态：

```text
CURRENT_STAGE:
CURRENT_STAGE_CONTRACT:
CURRENT_BASE:
CURRENT_HEAD:
LATEST_VERIFIED_CANDIDATE:
LUNA_GATE_STATUS:
ARCHITECTURE_STATUS:
OPEN_BLOCKER_SET:
```

如果已有有效 Stage Contract，按该阶段继续。

如果阶段已通过 required gate 但尚未架构闭合：
- 生成 `STAGE_CLOSURE_AND_NEXT_STAGE` packet；
- 调用 Sol Max。

如果无法确定当前 Stage Contract：
- 不自行发明长期阶段目标；
- 汇总现状后由 Sol Max 确立。

## 6. 下一阶段确定

下一阶段的正式目标、范围、禁止事项和 exit criteria 由 Sol Max 确立。

Coordinator 可以准备候选方向和证据，但不得把自己的建议当成 Stage Contract。

## 7. 冲突处理

遇到文档互相冲突时：
- 先区分“事实冲突”还是“规范冲突”；
- 事实冲突以 exact Git/evidence 核验；
- 规范冲突升级 Sol Max；
- 不通过删除旧证据来解决冲突。
