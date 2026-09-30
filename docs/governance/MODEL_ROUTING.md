# MODEL_ROUTING.md

## 当前映射

| Role | Current model signal | Model family | Purpose |
|---|---|---|---|
| Coordinator | GPT-6.1 Sol Medium | GPT-6.1 Sol | 日常总控、调度、汇总、路由 |
| Architect | GPT-6.1 Sol Max | GPT-6.1 Sol | 架构、invariant、阶段闭合、下一阶段 |
| Worker | GPT-6 Luna Max | GPT-6 Luna | 实际工程调查、实现、repair、测试/证据 |
| Independent Gate | GPT-6 Luna High | GPT-6 Luna | whole-candidate 独立门禁 |

本表只记录当前模型映射，不改变角色职责或开发流程，也不追溯改写既有 ADR、decision authority、阶段报告或 exact-SHA 证据。角色定义优先于模型名称；模型信号变化不改变职责边界。

## Coordinator — Sol Medium

可以：
- 同步项目状态；
- 拆任务；
- 调度 Luna Max；
- 汇总 blocker；
- 组织 batch repair；
- 组织集中 build/test；
- 准备 Sol Max / Luna High packet；
- 依据已有 architecture contract 做工程级决策。

不可以：
- 自行改变 frozen architecture/invariant；
- 自行降低 gate 标准；
- 代替 Sol Max 确立新阶段；
- 代替 Luna High 做独立 gate。

## Worker — Luna Max

默认用于：
- Scout；
- production implementation；
- repair；
- tests/fixtures；
- canary implementation；
- failure/root-cause analysis；
- evidence collection。

Worker 只向 Coordinator 汇报。

## Architect — Sol Max

只处理：
1. 新 architecture contract；
2. frozen invariant 变化或解释冲突；
3. 架构级 blocker；
4. 当前阶段架构闭合；
5. 下一 Stage Contract 确立。

Sol Max 不做进度跟踪、普通 repair、普通测试分析。

## Independent Gate — Luna High

输入应尽量只包含：
- requirement / Stage Contract；
- frozen invariants；
- exact base/candidate；
- diff scope；
- tests；
- real canary；
- negative evidence；
- known limitations。

输出仅：
- `PASS`
- `BLOCKED_IMPLEMENTATION`
- `BLOCKED_ARCHITECTURE`

Luna High 不直接联系 Sol Max；结果返回 Coordinator。

## 路由原则

```text
Worker findings
    ↓
Coordinator
    ├─ implementation/evidence → batch repair with Luna Max
    └─ architecture → consolidated packet → Sol Max

Candidate ready
    ↓
Luna High
    ├─ PASS → Stage Closure Packet → Sol Max
    ├─ BLOCKED_IMPLEMENTATION → batch repair
    └─ BLOCKED_ARCHITECTURE → consolidated packet → Sol Max
```

不设置 Sol Max 固定调用次数；正确的职责边界自然控制调用。
