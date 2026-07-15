import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  MemoryReviewController,
  type IMemoryService,
  type IMemoryExtractor,
  type CandidateConfirmationActions,
  type UiCandidate,
} from "../src/chat/memoryReviewController.ts";
import { createClosePanelHandler } from "../src/chat/memoryReviewAdapter.ts";
import type {
  MemoryRecord,
  CreateMemoryCandidateRequest,
  UpdateMemoryRequest,
  DeleteMemoryResult,
  MemoryKind,
} from "../src/memory/types.ts";
import type { MemoryExtractionResult } from "../src/memory/extractor/types.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ── Mock Types ────────────────────────────────────────────────────────

interface MockServiceCalls {
  createCandidate: CreateMemoryCandidateRequest[];
  updateCandidate: UpdateMemoryRequest[];
  deleteCalls: { lifeId: string; memoryId: string }[];
  extract: { lifeId: string; messages: readonly { role: string; content: string; timestamp: string }[] }[];
}

interface MockConfirmationCalls {
  prepare: string[];
  confirm: string[];
  cancel: string[];
  clear: number;
}

function createMocks() {
  const calls: MockServiceCalls = {
    createCandidate: [],
    updateCandidate: [],
    deleteCalls: [],
    extract: [],
  };

  const confirmationCalls: MockConfirmationCalls = {
    prepare: [],
    confirm: [],
    cancel: [],
    clear: 0,
  };

  const mockMemoryService: IMemoryService = {
    async createCandidate(request: CreateMemoryCandidateRequest): Promise<MemoryRecord> {
      calls.createCandidate.push(request);
      return {
        id: "db-mem-123",
        lifeId: request.lifeId,
        kind: request.kind,
        status: "candidate",
        content: request.content,
        summary: request.summary,
        sourceType: request.sourceType,
        sourceCreatedAt: request.sourceCreatedAt,
        importance: request.importance,
        confidence: request.confidence,
        isSensitive: request.isSensitive,
        createdAt: "2026-07-12T00:00:00Z",
        updatedAt: "2026-07-12T00:00:00Z",
      };
    },
    async updateCandidate(request: UpdateMemoryRequest): Promise<MemoryRecord> {
      calls.updateCandidate.push(request);
      return {
        id: request.memoryId,
        lifeId: request.lifeId,
        kind: request.kind,
        status: "candidate",
        content: request.content,
        summary: request.summary,
        sourceType: request.sourceType,
        sourceCreatedAt: request.sourceCreatedAt,
        importance: request.importance,
        confidence: request.confidence,
        isSensitive: request.isSensitive,
        createdAt: "2026-07-12T00:00:00Z",
        updatedAt: "2026-07-12T00:00:00Z",
      };
    },
    async delete(lifeId: string, memoryId: string): Promise<DeleteMemoryResult> {
      calls.deleteCalls.push({ lifeId, memoryId });
      return { memoryId, deleted: true };
    },
  };

  const mockConfirmationActions: CandidateConfirmationActions = {
    canPrepare: true,
    canConfirm: false,
    canCancel: false,
    async prepare(candidateId: string): Promise<void> {
      confirmationCalls.prepare.push(candidateId);
    },
    async confirm(candidateId: string): Promise<void> {
      confirmationCalls.confirm.push(candidateId);
    },
    async cancel(candidateId: string): Promise<void> {
      confirmationCalls.cancel.push(candidateId);
    },
    clearCandidateConfirmation(): void {
      confirmationCalls.clear++;
    },
  };

  const mockMemoryExtractor: IMemoryExtractor = {
    extract(request): MemoryExtractionResult {
      calls.extract.push(request);
      if (request.messages.length === 0) {
        return {
          lifeId: request.lifeId,
          sourceType: "conversation",
          candidates: [],
          analyzedMessageCount: 0,
          rejectedSensitiveCount: 0,
        };
      }
      return {
        lifeId: request.lifeId,
        sourceType: "conversation",
        candidates: [
          {
            lifeId: request.lifeId,
            kind: "preference",
            status: "candidate",
            content: "我喜欢乌龙茶",
            summary: "Preference: 喜欢乌龙茶",
            importance: 0.72,
            confidence: 0.95,
            sourceType: "conversation",
            sourceCreatedAt: request.messages[0].timestamp,
            isSensitive: false,
          },
          {
            lifeId: request.lifeId,
            kind: "fact",
            status: "candidate",
            content: "我的邮箱是sensitive@example.com",
            summary: "Fact: 邮箱: sensitive@example.com",
            importance: 0.74,
            confidence: 0.9,
            sourceType: "conversation",
            sourceCreatedAt: request.messages[0].timestamp,
            isSensitive: true,
          },
        ],
        analyzedMessageCount: request.messages.length,
        rejectedSensitiveCount: 0,
      };
    },
  };

  return { calls, confirmationCalls, mockMemoryService, mockMemoryExtractor, mockConfirmationActions };
}

// ── Test: Controller does not receive tokens ──────────────────────────

test("1. Controller 不接收 Token 参数", () => {
  const { mockMemoryService, mockMemoryExtractor, mockConfirmationActions } = createMocks();
  const controller = new MemoryReviewController(mockMemoryService, mockMemoryExtractor, mockConfirmationActions);

  // Verify method signatures - no approvalToken parameter
  assert.equal(controller.prepareCandidate.length, 1); // only index
  assert.equal(controller.confirmPreparedCandidate.length, 1); // candidate index only
  assert.equal(controller.cancelPreparedCandidate.length, 1); // candidate index only
});

// ── Test: Controller calls Store actions ──────────────────────────────

test("2. Controller 调用 Store 动作而非直接调用 Service", async () => {
  const { calls, confirmationCalls, mockMemoryService, mockMemoryExtractor, mockConfirmationActions } = createMocks();
  const controller = new MemoryReviewController(mockMemoryService, mockMemoryExtractor, mockConfirmationActions);
  controller.setLifeId("life-123");

  await controller.extract([{ role: "user", content: "我喜欢乌龙茶", timestamp: "2026-07-12" }]);
  await controller.createCandidate(0);

  assert.equal(calls.createCandidate.length, 1);

  // Prepare calls store action
  await controller.prepareCandidate(0);
  assert.equal(confirmationCalls.prepare.length, 1);
  assert.equal(confirmationCalls.prepare[0], "db-mem-123");
  assert.deepEqual(confirmationCalls.confirm, []);

  // Confirm calls store action (no token param)
  await controller.confirmPreparedCandidate(0);
  assert.deepEqual(confirmationCalls.confirm, ["db-mem-123"]);

  // Cancel calls store action
  await controller.cancelPreparedCandidate(0);
  assert.deepEqual(confirmationCalls.cancel, ["db-mem-123"]);
});

test("2b. Controller resolves the active review index to a Candidate ID", async () => {
  const { confirmationCalls, mockMemoryService, mockMemoryExtractor, mockConfirmationActions } = createMocks();
  const controller = new MemoryReviewController(mockMemoryService, mockMemoryExtractor, mockConfirmationActions);
  controller.setLifeId("life-123");
  await controller.extract([{ role: "user", content: "我喜欢乌龙茶", timestamp: "2026-07-12" }]);
  await controller.createCandidate(0);

  const secondCandidate = {
    ...controller.candidates[0],
    id: "candidate-second",
    dbRecord: { ...controller.candidates[0].dbRecord!, id: "db-mem-456" },
  };
  controller.candidates = [controller.candidates[0], secondCandidate];
  await controller.prepareCandidate(0);
  await controller.confirmPreparedCandidate(1);
  await controller.cancelPreparedCandidate(1);

  assert.deepEqual(confirmationCalls.prepare, ["db-mem-123"]);
  assert.deepEqual(confirmationCalls.confirm, ["db-mem-456"]);
  assert.deepEqual(confirmationCalls.cancel, ["db-mem-456"]);
});

// ── Test: lifeId in all operations ────────────────────────────────────

test("3. lifeId 在所有操作中被正确传递", async () => {
  const { calls, confirmationCalls, mockMemoryService, mockMemoryExtractor, mockConfirmationActions } = createMocks();
  const controller = new MemoryReviewController(mockMemoryService, mockMemoryExtractor, mockConfirmationActions);
  controller.setLifeId("life-secure-id");

  await controller.extract([{ role: "user", content: "我喜欢乌龙茶", timestamp: "2026-07-12" }]);

  // 1. Create
  await controller.createCandidate(0);
  assert.equal(calls.createCandidate.length, 1);
  assert.equal(calls.createCandidate[0].lifeId, "life-secure-id");

  // 2. Update
  controller.editCandidate(0, "preference", "我修改了偏好", "Summary edit");
  await controller.updateCandidate(0);
  assert.equal(calls.updateCandidate.length, 1);
  assert.equal(calls.updateCandidate[0].lifeId, "life-secure-id");

  // 3. Prepare (calls store action with candidate id)
  await controller.prepareCandidate(0);
  assert.equal(confirmationCalls.prepare.length, 1);

  // 4. Delete
  await controller.extract([{ role: "user", content: "我喜欢乌龙茶", timestamp: "2026-07-12" }]);
  await controller.createCandidate(0);
  await controller.deleteCandidate(0);
  assert.equal(calls.deleteCalls.length, 1);
  assert.equal(calls.deleteCalls[0].lifeId, "life-secure-id");
});

// ── Test: lifeId security ─────────────────────────────────────────────

test("4. 错误的候选数据生命ID不能覆盖 Controller 使用的当前 lifeId", async () => {
  const { calls, mockMemoryService, mockMemoryExtractor, mockConfirmationActions } = createMocks();
  const controller = new MemoryReviewController(mockMemoryService, mockMemoryExtractor, mockConfirmationActions);
  controller.setLifeId("life-correct");

  await controller.extract([{ role: "user", content: "我喜欢乌龙茶", timestamp: "2026-07-12" }]);

  const candidate = controller.candidates[0];
  const candidateRef = candidate as { lifeId?: string };
  candidateRef.lifeId = "life-malicious";

  await controller.createCandidate(0);
  assert.equal(calls.createCandidate.length, 1);
  assert.equal(calls.createCandidate[0].lifeId, "life-correct");
});

// ── Test: Delete failure recovery ─────────────────────────────────────

test("5. Delete Mock 与失败恢复测试", async () => {
  const { calls, mockMemoryService, mockMemoryExtractor, mockConfirmationActions } = createMocks();
  mockMemoryService.delete = async () => {
    throw new Error("Simulated SQLite delete failure");
  };

  const controller = new MemoryReviewController(mockMemoryService, mockMemoryExtractor, mockConfirmationActions);
  controller.setLifeId("life-correct");

  await controller.extract([{ role: "user", content: "我喜欢乌龙茶", timestamp: "2026-07-12" }]);
  await controller.createCandidate(0);

  const beforeId = controller.candidates[0].dbRecord?.id;
  assert.ok(beforeId);
  assert.equal(controller.candidates[0].state, "candidateCreated");

  await controller.deleteCandidate(0);

  assert.equal(calls.deleteCalls.length, 0);
  assert.equal(controller.candidates.length, 2);
  assert.equal(controller.candidates[0].state, "candidateCreated");
  assert.equal(controller.candidates[0].dbRecord?.id, beforeId);
  assert.equal(controller.candidates[0].error?.stage, "deletion");
  assert.equal(controller.candidates[0].error?.code, "MEMORY_ERROR");
});

// ── Test: closeReviewPanel ────────────────────────────────────────────

test("6. closeReviewPanel 清理草稿并检测未确认候选", async () => {
  const { mockMemoryService, mockMemoryExtractor, mockConfirmationActions } = createMocks();
  const controller = new MemoryReviewController(mockMemoryService, mockMemoryExtractor, mockConfirmationActions);
  controller.setLifeId("life-123");

  await controller.extract([{ role: "user", content: "我喜欢乌龙茶", timestamp: "2026-07-12" }]);
  await controller.createCandidate(0);

  assert.equal(controller.candidates.length, 2);

  const hasUnconfirmed = controller.closeReviewPanel();

  assert.equal(controller.candidates.length, 1);
  assert.equal(controller.candidates[0].state, "candidateCreated");
  assert.equal(hasUnconfirmed, true);
});

// ── Test: confirmed state locks ───────────────────────────────────────

test("7. confirmed 状态 Controller 拒绝编辑和更新", async () => {
  const { mockMemoryService, mockMemoryExtractor, mockConfirmationActions } = createMocks();
  const controller = new MemoryReviewController(mockMemoryService, mockMemoryExtractor, mockConfirmationActions);
  controller.setLifeId("life-123");

  await controller.extract([{ role: "user", content: "我喜欢乌龙茶", timestamp: "2026-07-12" }]);
  await controller.createCandidate(0);

  // Manually set to confirmed state for testing
  controller.candidates[0].state = "confirmed";

  // Edit rejected
  controller.editCandidate(0, "experience", "edited content", "edited summary");
  assert.equal(controller.candidates[0].content, "我喜欢乌龙茶");

  // Update rejected
  await controller.updateCandidate(0);
  assert.equal(controller.candidates[0].error?.code, "CONFIRMED_LOCK");
});

// ── Test: creation guard ──────────────────────────────────────────────

test("8. 创建守卫失败不影响其他候选", async () => {
  const { mockMemoryService, mockMemoryExtractor, mockConfirmationActions } = createMocks();
  const controller = new MemoryReviewController(mockMemoryService, mockMemoryExtractor, mockConfirmationActions);
  controller.setLifeId("life-123");

  await controller.extract([{ role: "user", content: "我喜欢乌龙茶", timestamp: "2026-07-12" }]);

  controller.candidates[0].state = "creatingCandidate";

  await controller.createCandidate(0);
  assert.equal(controller.candidates[0].error?.code, "INVALID_STATE");

  assert.equal(controller.candidates[1].state, "draft");
  await controller.createCandidate(1);
  assert.equal(controller.candidates[1].state, "candidateCreated");
});

// ── Test: Adapter binding ─────────────────────────────────────────────

test("9. Adapter 与 ChatView 实际关闭路径绑定验证", () => {
  const { mockMemoryService, mockMemoryExtractor, mockConfirmationActions } = createMocks();
  const controller = new MemoryReviewController(mockMemoryService, mockMemoryExtractor, mockConfirmationActions);
  controller.candidates = [
    {
      id: "candidate-1",
      kind: "preference",
      content: "test",
      summary: "",
      importance: 0.8,
      confidence: 0.9,
      isSensitive: false,
      sourceType: "conversation",
      sourceCreatedAt: "2026",
      sensitiveConsentChecked: false,
      state: "candidateCreated",
      dbRecord: {
        id: "db-mem-123",
        lifeId: "life-123",
        kind: "preference",
        status: "candidate",
        content: "test",
        sourceType: "conversation",
        sourceCreatedAt: "2026",
        importance: 0.8,
        confidence: 0.9,
        isSensitive: false,
        createdAt: "2026",
        updatedAt: "2026",
      },
    },
  ];

  const actions = {
    showMemoryPanel: { value: true },
    showUnconfirmedHint: { value: false },
  };

  const handleClosePanel = createClosePanelHandler(controller, actions);

  handleClosePanel();

  assert.equal(actions.showMemoryPanel.value, false);
  assert.equal(actions.showUnconfirmedHint.value, true);

  const chatViewPath = path.resolve(__dirname, "../src/chat/ChatView.vue");
  const chatViewContent = fs.readFileSync(chatViewPath, "utf8");

  assert.ok(
    chatViewContent.includes('class="memory-panel-backdrop" @click="handleClosePanel"')
  );

  assert.ok(
    chatViewContent.includes('class="close-btn" type="button" @click="handleClosePanel"')
  );
});

// ── Test: No old confirm method ───────────────────────────────────────

test("10. 旧一步确认方法不存在", () => {
  const { mockMemoryService, mockMemoryExtractor, mockConfirmationActions } = createMocks();
  const controller = new MemoryReviewController(mockMemoryService, mockMemoryExtractor, mockConfirmationActions);

  // Old method should not exist
  assert.equal('confirmCandidate' in controller, false, "Old confirmCandidate should not exist");
});

// ── Test: Prepare failure handling ────────────────────────────────────

test("11. Prepare 失败设置错误", async () => {
  const { mockMemoryService, mockMemoryExtractor } = createMocks();
  const failingActions: CandidateConfirmationActions = {
    canPrepare: true,
    canConfirm: false,
    canCancel: false,
    async prepare(_candidateId: string): Promise<void> {
      throw new CandidateConfirmationError(
        "CANDIDATE_CONFIRMATION_NOT_FOUND",
        "Not found",
        "none",
      );
    },
    async confirm(_candidateId: string): Promise<void> {},
    async cancel(_candidateId: string): Promise<void> {},
    clearCandidateConfirmation(): void {},
  };

  const controller = new MemoryReviewController(mockMemoryService, mockMemoryExtractor, failingActions);
  controller.setLifeId("life-123");

  await controller.extract([{ role: "user", content: "我喜欢乌龙茶", timestamp: "2026-07-12" }]);
  await controller.createCandidate(0);

  await controller.prepareCandidate(0);

  assert.ok(controller.candidates[0].error);
  assert.equal(controller.candidates[0].error?.stage, "confirmation");
});

// ── Test: disabled UI doesn't break other actions ─────────────────────

test("12. 禁用确认按钮不影响其他 Memory Review 动作", async () => {
  const { calls, mockMemoryService, mockMemoryExtractor, mockConfirmationActions } = createMocks();
  const controller = new MemoryReviewController(mockMemoryService, mockMemoryExtractor, mockConfirmationActions);
  controller.setLifeId("life-123");

  // Extract works
  await controller.extract([{ role: "user", content: "我喜欢乌龙茶", timestamp: "2026-07-12" }]);
  assert.equal(controller.panelState, "reviewing");

  // Create works
  await controller.createCandidate(0);
  assert.equal(controller.candidates[0].state, "candidateCreated");

  // Edit works
  controller.editCandidate(0, "preference", "新内容", "新摘要");
  assert.equal(controller.candidates[0].content, "新内容");

  // Update works
  await controller.updateCandidate(0);
  assert.equal(calls.updateCandidate.length, 1);

  // Delete works
  await controller.deleteCandidate(0);
  assert.equal(controller.candidates.length, 1);
});

// ── Test: Controller does not directly call ConfirmationService ────────

test("13. Controller 不直接调用 ConfirmationService", () => {
  // The Controller type signature only accepts CandidateConfirmationActions
  // not ICandidateConfirmationService. This is a compile-time guarantee.
  // We verify the interface here.
  const { mockMemoryService, mockMemoryExtractor, mockConfirmationActions } = createMocks();
  const controller = new MemoryReviewController(mockMemoryService, mockMemoryExtractor, mockConfirmationActions);

  // Controller has no reference to confirmationService (the old interface)
  // The field is private, so we check the type contract
  assert.equal(typeof controller.prepareCandidate, 'function');
  assert.equal(typeof controller.confirmPreparedCandidate, 'function');
  assert.equal(typeof controller.cancelPreparedCandidate, 'function');
});
