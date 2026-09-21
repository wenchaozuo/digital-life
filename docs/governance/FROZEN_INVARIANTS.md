# FROZEN_INVARIANTS.md

> 本文件记录“普通实现绝对不得自行改变”的长期不变量。
>
> **修改本文件中的语义要求必须经过 Sol 明确架构裁决。**
> 如果当前代码与本文件冲突，应视为 blocker，而不是修改本文件迁就实现。

## F-01 Authority 必须显式、可验证、可撤销

所有高风险能力必须来自明确 authority。  
不得通过隐式全局状态、未治理 registry、环境继承或路径猜测扩大 authority。

## F-02 Host-owned authority 不得被 Vita 自行制造

需要 Host 授权的能力必须由 Host 产生/持有其权威来源。  
Vita 可以 validate / narrow，但不得自行生成等价 Host authority。

## F-03 Revocation 必须 fail-closed

授权撤销后：

- 不得继续 mutation；
- 不得自动 retry 获得等价权限；
- 不得使用 stale authority/evidence；
- 如适用，应能提供 `mutation after revoke = 0` 类 negative evidence。

## F-04 Cancellation fence 后不得发生被禁止副作用

一旦进入明确取消/终止边界：

- 后续 mutation 必须受控；
- 不得因为异步竞态越过 fence；
- 必要时必须提供 syscall/行为级 negative evidence。

## F-05 高风险 filesystem mutation 必须遵守已冻结安全模型

不得为了方便重新引入：

- 未批准 pathname reopen；
- 不受治理的 root；
- 绕过 handle-relative / authority-bound 语义的后门路径。

具体阶段要求以已批准架构决定为准。

## F-06 Persistence 与 recovery 必须保持原子性和可验证性

涉及 journal / prepared / started / recovery 的逻辑：

- 不得把不满足 expected 条件的操作写入不可逆状态；
- crash/restart 后必须保持已冻结恢复语义；
- 不得通过“自动猜测”扩大恢复 authority。

## F-07 Expected / identity / hash 等绑定不得后移到危险副作用之后

凡已冻结要求规定 expected identity/hash/evidence 必须在 mutation/journal 前验证的，Codex 不得将验证后移。

## F-08 生产路径不得引入未经批准的 authority registry

新增全局/生产 authority registry 默认禁止。  
如确需引入，必须 `SOL_REQUIRED`。

## F-09 Workspace / profile / Host root 暴露遵循最小权限

child/process/agent 不得获得超出任务要求的：

- user profile；
- Host root；
- workspace；
- credentials；
- toolchain authority。

## F-10 Toolchain / source-of-truth 必须使用冻结的权威来源

如果当前阶段要求 Host exact toolchain / fresh source / per-action snapshot：

- 不得复用不允许的 session-start snapshot；
- 不得通过 PATH / user profile 隐式解析替代 exact authority；
- 不得用 stale cached source 伪装 fresh source。

具体执行条件以当前架构决定为准。

## F-11 Migration / Schema 变更默认禁止

任何 migration / persistent schema 变化均视为 RED，并触发 `SOL_REQUIRED`。

不得因为代码需要新字段就自行加入 migration。

## F-12 外部/冻结协议兼容优先

除非 Sol 明确批准：

- 不改变冻结 IPC/API/protocol；
- 不改变 frozen storage key；
- 不改变已冻结 capability/recovery contract；
- 不以“重构更干净”为理由破坏兼容。

## F-13 Real canary 不得由 mock 替代

当 requirement 要求真实 Host / filesystem / SQLite / process / toolchain / crash 行为时：

- mock PASS 不能关闭 gate；
- fixture PASS 不能自动关闭 gate；
- compile PASS 不能关闭 gate。

## F-14 安全结论必须有 negative evidence

安全敏感阶段必须证明禁止行为没有发生，而不仅仅是正确路径成功。

典型证据：

- unauthorized mutation = 0
- mutation after revoke = 0
- automatic retry after revoke = 0
- production authority registry = 0
- pathname reopen = 0
- stale evidence accepted = 0

## F-15 Gate 必须绑定 exact candidate SHA

- 非 exact SHA 不得最终 gate；
- repair 后新 SHA 必须重新 gate；
- 旧 candidate PASS 不自动继承；
- dirty tree 不可 final freeze。

## F-16 证据不足时 fail-closed

`No evidence != PASS`

无法建立 required proof 时结论必须是 `BLOCKED`。

## F-17 HIGH milestone 只有最终权威可冻结

Codex / 子代理不得自行宣布 HIGH milestone frozen。

标准：

`Codex Ready -> Luna High PASS -> Sol Final PASS -> FROZEN`
