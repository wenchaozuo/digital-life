# 执行效率规则与当前有效治理索引

**Governance revision:** v1.3 / 2026-10-02-efficiency-01  
**Authority:** 用户批准实施开发协议优化；Coordinator 直接维护本次治理文档。  
**Scope:** 调度、调查闭合、验证选择、报告、文档与临时目录生命周期。  
**Not authority:** 本文件不批准新的架构、证据 schema、缓存信任、正式续跑或 D32 门槛减免。

## 1. 有效入口与同步边界

- `AGENTS.md` 是短入口，完整职责见 `CODEX_DEVELOPMENT_PROTOCOL.md`；当前模型只以 `MODEL_ROUTING.md` 为配置事实源。
- 本文件是 v1.3 执行补充，取代通用规则中允许 Coordinator/Root 默认代替 Luna Build Owner 的兜底，以及要求 D32 闭合后自动建立下一阶段的通用表述。其他 frozen product/security/authority 语义不变。
- 原始目录：`E:\project\digital-life`，v1.3 通用治理文本的来源副本；其既有 dirty/untracked 内容不得当作可丢弃文件。本轮获准的调度澄清仅集成在唯一 Integration，不写原始目录。
- 当前 D32 Integration：`E:\project\digital-life-d32-final-gate-13d40b8`。2026-10-02 对 `9b7125a8945137fb207a7d38c07af3538136db63` 的只读核验是历史观察，发生在后续集成之前；它不是当前 HEAD、Gate 或 PASS。恢复任务时以 Git 重新核验当前 exact SHA 与 clean 状态。
- D32 已批准的完整 ADR、F-01 至 F-17、`SC-D32-V1.md` 和 §16.1.1–§16.1.5 supplement 以该 Integration 中的历史记录为准。原始目录的 ADR 空索引与不同 F-ID 列表不能替代它们；不按编号跨副本合并不变量。
- 既有 `ADR-D32-GOVERNANCE-V12-RECONCILIATION` 已将历史通用 no-worktree 引用更新为受控 Patch Worktree + 唯一 Integration；保留历史文字并读取 supersession，不重写旧决定。
- v1.3 治理同步已在先前受控集成节点完成，状态缓存记录为 COMPLETE 且不预填自身 commit SHA。本次获准的调度澄清在非正式执行节点单独集成；以后仍不得在正式执行中临时改文档、保持旧 SHA 却声称新候选，或继承旧 PASS。
- 通用规则与 D32 专项约束冲突时，用户当前指令和有效已批准架构/Stage Contract 控制；无法消解的架构冲突合并提交 Architect，普通工程问题批量交 Worker。

### D32 当前有效约束速查（不是替代原文）

| 项目 | 当前有效要求 | 决定来源 |
|---|---|---|
| 工作区 | 受控 Patch Worktree；唯一 Integration；普通 Patch 不 build/test/canary | v1.2 通用协议、Governance Reconciliation ADR |
| 进程证明 | Trace V2，CREATE 在 Continue 前校验，独立 Job accounting 与完整 cleanup | Process Event Trace V2 及 cleanup clarification |
| 正式缓存/目录 | discovery、Phase0 各有 fresh owner-bound root/空 CargoHome；normal target 保留；不复制旧缓存、不 target override、不 cargo clean | Compact Evidence、Fixture Budget、Inventory Authority ADR |
| 执行次序 | discovery 与独立 baseline pin → formal Phase0 → Phase1 → aggregate → required real cases/ordered modes → 独立 Gate → D32 closure | SC-D32-V1 与 §16.1.5 |
| 当前 outer schemas | fixture V7、discovery V2、baseline V2、Phase0 V8、release V9、aggregate V8 | PowerShell Content Authority V2 及后续澄清 |
| 保持的 schemas | Profile V2、Trace V2、fixture manifest v3、D31 seeder V2；blocked diagnostic V1 只有失败诊断权 | 同上；相关 D32 ADR |
| 有界归档诊断 | `D32_REGISTRY_TAR_USTAR_GNU_LONGNAME_V1`；SourceProof authority V3 / candidate V4 / registry proof V4 / compiler diagnostic authority+result V3 / census authority+result V2。均为诊断-only、Gate NONE；每次未来 census 使用新 authority 和独立 exact pins | ADR-D32-BOUNDED-REGISTRY-TAR-FORMAT-V1 与 ADR-D32-BOUNDED-REGISTRY-TAR-GNU-LONGNAME-V1 |
| PowerShell admission | 独立 caller pin、module-free pre-import、protected distribution/resolver proof、实际 origins 校验 | Content Authority V2 与 Windows/volume-root clarifications |
| 停止边界 | D32 完成、必要清理后停止；不建立 D33 Contract | Governance Reconciliation ADR、用户指令 |

命令 argv、jobs、timeouts、资源阈值、例外图像 identities、测试名和有序 modes 必须读取有效 ADR/Contract，不从此摘要猜测。以上 schema 表只供查找，不能使缺少最新 mandatory fields 的同版本草稿变成有效记录。

## 2. 低成本但完整的启动

首次接手、治理修订变化、架构争议、Gate 或阶段闭合时，Coordinator 完整读取协议及适用专项决定。后续同修订轮次仍核验 Git、必要状态与当前任务约束，但不反复复制全部历史。

首次读取后保留已读文档路径、内容 SHA-256、治理修订、Stage Contract 和 Integration 路径。恢复时比较 fingerprints；变化文档及其依赖完整重读，不以旧摘要替代变化规则。Worker 只读取任务必要上下文和适用入口，不反复读取无关历史。

状态页必须标注历史快照/核验时间/证据范围。不把自己的待提交 SHA 写进同一 commit；运行中的 attempt journal 放在该次允许的外部证据位置。没有新证据时写 UNKNOWN/NOT VERIFIED，而不是推测进度或重建旧 PASS。

## 3. 并行任务图与唯一 Build Owner

Coordinator 下发：Goal、上下文、frozen constraints、mode、写范围、依赖/接口、产物、验证与停止条件；不规定未冻结的逐行实现步骤。

- 按实际可用并发槽安排；当前四槽包含 Coordinator，最多三个并行 Luna。Patch Worktree 上限仍为三个，不代表同时还能增加第四个 Worker。
- 一个 Luna 为唯一 Integration / Build Owner；可兼任一个调查/修复任务。其他 Luna 做独立范围的 Scout/patch/test设计，普通 Patch Worktree 不编译。
- 同一文件/共享 schema 必须只有一个写 owner；公共接口与依赖先约定，有依赖的任务顺序执行，不以无意义任务填满槽位。
- Worker 的普通方法选择和实现阻塞在冻结范围内自主处理，整轮返回 Coordinator；需要新权限或架构变化时停止对应危险执行。
- Coordinator 默认不实现产品、不分析普通构建错误、不接替 Build Owner。用户明确指定 Coordinator 直接维护治理文档的例外，只授权本次文档操作。
- 最终 Luna High 与 candidate 实现人员独立；不得让实现 Worker 审核自己的候选后声称 independent Gate。

## 4. Repair wave 与调查闭合

流程：`bounded census → complete blocker set → root/dependency clustering → patch batch → integration → affected validation → formal readiness`。

每轮 census 必须报告已查/未查：入口参数、producer、consumer、nested references、schema/types、path/identity binding、positive path、negative path、failure diagnostics、cleanup、相邻调用。未覆盖范围写明原因；不得仅用测试数量声称 whole-chain 闭合。

每个 blocker 至少包含 ID、根因假设、证据路径、影响模块、依赖/同源关系、修复 owner、所需 closure proof。Coordinator 先去重分类，implementation/evidence 交 Luna batch repair，确认的架构冲突合并一个 Architect packet。

发现普通 blocker 后继续安全且有价值的调查，不能发现一个就停止整轮并启动全量测试。安全边界失败停止对应执行，不继续危险操作；可以继续只读调查。不能保证一次发现所有缺陷，但必须对声明的调查范围负责。

连续出现同类修复遗漏时，下一轮优先补公共契约/入口覆盖和根因调查，不机械重复相同昂贵尝试。新 blocker 区分 inherited defect、repair regression、environment、missing evidence；归类以证据为准，不自动归咎旧代码。

## 5. 验证分层与昂贵流程前准入

| 层 | 内容 | 触发 |
|---|---|---|
| L0 | 静态、schema、pure policy、参数/类型/解析、保留 raw logs 回放 | 每批相关修改 |
| L1 | 合法 admission 下的短时真实入口、捕获、cleanup 与跨进程记录链 | 运行边界变更后、昂贵执行前 |
| L2 | affected integration tests 和相邻负向回归 | batch 集成后 |
| L3 | Stage Contract required full matrix、required canary | 稳定候选与准入条件满足后 |
| L4 | exact clean candidate whole-candidate independent Gate | required local evidence 完整后 |

Build Owner 在执行前给出 impact map：改动 → 受影响契约 → 必要 positive/negative tests → 可仅作参考的旧证据 → 必须重跑项。重复测试不是默认安全策略；删除 required tests 也不是优化。

parser 修复优先回放既有原始字节；参数/serialization 修复先执行真实调用形状的廉价验证。公共 runner 变更同时验证不同入口、集合 round-trip、empty ignored list、分隔/summary、failure payload 与 cleanup；不得用静态匹配或大量 synthetic counts 替代运行正路径。

L1 必须遵守现有 caller pins、启动/admission/trace 和授权边界；不授权额外 helper、Cargo/network、正式 root 或新的启动模式。没有合法廉价正路径时标明缺口并停在对应准入点，不能绕过 frozen requirement。

昂贵启动前必须有可核验的 census、公共契约验证、入口参数实际值、所需权限/pins、candidate clean 与唯一 owner。§16.1.5 聚合及其唯一 bootstrap 例外保持原义，不能用本节新增清单代替。

L0–L2 是开发证据，不关闭 L3/L4；required negative evidence 和 real canary 不减。新 SHA 不自动继承旧 PASS，正式重建范围按有效 Stage Contract/ADR，而不是 Coordinator 自行缩小。

## 6. 缓存与目录的不同生命周期

证据目录、CargoHome、target 和编译器缓存是不同对象。normal target 可以保留，不执行例行 cargo clean；普通 Patch Worktree 不生成自己的 target。允许缓存的其他阶段需记录来源、隔离与失效依据，不与另一个 Build Owner 并发共享可写 target。

D32 discovery/Phase0 的 fresh empty CargoHome、fixed paths/commands、no cache copy/no target override 保持不变；Phase1 仅按既有规则使用该 Phase0 的 populated CargoHome。开发日志回放不需要再 fetch；其他非门禁开发运行仍需既有授权与 admission，不能以 DEVELOPMENT_ONLY 标签豁免安全规则。

## 7. Attempt ledger 与禁止盲目重试

每次获准昂贵执行记录唯一 attempt ID、role/owner、exact SHA、pins、实际启动时间/次数、ordered commands、完成/失败命令、原始日志、exit/cleanup、证据位置和重试条件。优先复用现有记录字段与外部 journal，不改变 frozen evidence schema。

没有记录的清理不能当成功；超时不自动重启。诊断保留原始 primary error、secondary capture error 与 LastCompleted context，禁止最后一次成功 exit=0 隐藏后续 wrapper failure。

保留失败输出用于回放，不因此获得正式 checkpoint/PASS。跨 attempt/跨 SHA 正式续跑、共享下载缓存或跨 candidate 证据复用必须另行批准。

## 8. 静默窗口、汇报与异常干预

任务下发和完成后向用户简报目标/产物、验证范围、blocker 与下一步。执行期采用事件返回/被动等待保持会话，不轮询状态，不索要中间报告，不重复审查 partial findings。使用 `wait_agent` 被动等待时，每次最长 10 分钟，收到事件可提前唤醒；此等待粒度不是状态轮询。

Coordinator 默认 90 分钟没有完成/阻塞事件后允许一次异常检查；该异常检查窗口保持不变。长任务按已批准 command deadline 和 worker packet 指定保守 watchdog。该检查只判断卡死、资源、权限和进程所有权，不是周期进度跟踪；在合理执行时继续被动等待。停止/重启前保留日志，核验属于本任务的进程，并遵守授权边界。watchdog 不扩大或缩小 frozen timeout。

HIGH 实现/门禁期间 Sol Max 保持 inactive；仅架构触发、Luna High BLOCKED_ARCHITECTURE、用户改变 frozen requirement、高可信架构失效证据或 PASS 后 final closure 介入。普通 implementation blockers 经 Coordinator 回 Luna Max，不升级 Architect。

Sol token 约 15% 是调度优化目标，不是虚构计量结果；无可靠用量数据不报告实际比例。只在批次完成后整理已有 duration、cold/warm build、重复启动、blocker wave 和磁盘数据，不另设高频监控。

## 9. 清理与阶段停止

临时目录登记 exact path、owner、用途、证据引用、活动进程、回收条件。Patch 导出并集成/放弃后回收；清理前核验不存在遗漏 patch 与依赖。失败证据与隔离输出按引用关系保留，提炼必要 regression 样本后，确已失去复现/审计价值且获授权时再清理大目录。

保留源码、有效治理历史、必要 fixtures/证据、可复用 normal build cache。不删除原始 dirty 内容、真实 Codex config/auth/provider credentials，不对仓库根或磁盘根递归删除。优先可恢复清理，记录移除范围及释放空间。

D32 全部 required gates 与 Sol closure 完成后，执行已授权的目录/空间整理，报告结果并停止；不得自动建立 D33 目标或 Contract。

## 10. 尚未批准的后续提案

以下只能作为 Architect packet 候选，不是生效规则：

1. D32 fresh CargoHome 与受验证共享依赖/编译缓存分离；缓存键覆盖 toolchain/locks/source/features/build scripts/flags/env/config，隔离 credentials 与写入权限。
2. 同 SHA 正式 checkpoint 续跑，以及新 SHA 的 proof invalidation/dependency graph；不能重标旧 PASS。
3. 固定资源阈值与全局 writer census 改为精确 target owner/identity lease；需证明不削弱互斥与容量要求。
4. 调整重复 inventory/full/focused required commands；需批准修改具体 Stage Contract/ADR，不能只改通用测试分层。

优先顺序：先落实通用执行效率规则与廉价工具链验证，再评估上述架构变更的收益和风险。不得为了优化当前 D32 重开无关架构或下一阶段。
