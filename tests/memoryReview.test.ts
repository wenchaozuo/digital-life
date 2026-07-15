import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  MemoryReviewController,
  type IMemoryService,
  type IMemoryExtractor,
  type ICandidateConfirmationService,
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
import type {
  PreparedCandidateConfirmation,
  CandidateConfirmationResult,
  CancelCandidateConfirmationResult,
} from "../src/memory/candidateConfirmationTypes.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

interface MockServiceCalls {
  createCandidate: CreateMemoryCandidateRequest[];
  updateCandidate: UpdateMemoryRequest[];
  prepareCandidate: string[];
  confirmCandidate: { candidateId: string; approvalToken: string }[];
  cancelCandidate: { candidateId: string; approvalToken: string }[];
  deleteCalls: { lifeId: string; memoryId: string }[];
  extract: { lifeId: string; messages: readonly { role: string; content: string; timestamp: string }[] }[];
}

function createMocks() {
  const calls: MockServiceCalls = {
    createCandidate: [],
    updateCandidate: [],
    prepareCandidate: [],
    confirmCandidate: [],
    cancelCandidate: [],
    deleteCalls: [],
    extract: [],
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

  const mockConfirmationService: ICandidateConfirmationService = {
    async prepareCandidateConfirmation(candidateId: string): Promise<PreparedCandidateConfirmation> {
      calls.prepareCandidate.push(candidateId);
      return {
        candidateId,
        expectedRevision: 1,
        kind: "preference",
        content: "Test content",
        summary: "Test summary",
        isSensitive: false,
        source: {
          sourceType: "conversation",
          inferenceStatus: "completed",
        },
        confirmationRequirement: "standard",
        approvalToken: "a".repeat(64),
        expiresAt: new Date(Date.now() + 300000).toISOString(),
      };
    },
    async confirmCandidateMemory(candidateId: string, approvalToken: string): Promise<CandidateConfirmationResult> {
      calls.confirmCandidate.push({ candidateId, approvalToken });
      return {
        candidateId,
        confirmedMemoryId: "confirmed-mem-123",
        outcome: "confirmed",
      };
    },
    async cancelCandidateConfirmationApproval(candidateId: string, approvalToken: string): Promise<CancelCandidateConfirmationResult> {
      calls.cancelCandidate.push({ candidateId, approvalToken });
      return {
        candidateId,
        cancelled: true,
      };
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

  return { calls, mockMemoryService, mockMemoryExtractor, mockConfirmationService };
}

test("1. 普通候选确认流程断言 (prepare + confirm)", async () => {
  const { calls, mockMemoryService, mockMemoryExtractor, mockConfirmationService } = createMocks();
  const controller = new MemoryReviewController(mockMemoryService, mockMemoryExtractor, mockConfirmationService);
  controller.setLifeId("life-123");

  await controller.extract([{ role: "user", content: "我喜欢乌龙茶", timestamp: "2026-07-12" }]);
  await controller.createCandidate(0);

  // Asserting parameters passed to createCandidate
  assert.equal(calls.createCandidate.length, 1);
  assert.equal(calls.createCandidate[0].lifeId, "life-123");

  // Step 1: Prepare candidate
  const prepared = await controller.prepareCandidate(0);
  assert.ok(prepared);
  assert.equal(calls.prepareCandidate.length, 1);
  assert.equal(calls.prepareCandidate[0], "db-mem-123");

  // Step 2: Confirm candidate with token
  await controller.confirmCandidate(0, prepared!.approvalToken);

  // Asserting parameters passed to confirm
  assert.equal(calls.confirmCandidate.length, 1);
  assert.deepEqual(calls.confirmCandidate[0], {
    candidateId: "db-mem-123",
    approvalToken: "a".repeat(64),
  });
  assert.equal(controller.candidates[0].state, "confirmed");
});

test("2. 敏感候选确认流程断言 (prepare + confirm)", async () => {
  const { calls, mockMemoryService, mockMemoryExtractor, mockConfirmationService } = createMocks();
  const controller = new MemoryReviewController(mockMemoryService, mockMemoryExtractor, mockConfirmationService);
  controller.setLifeId("life-123");

  await controller.extract([{ role: "user", content: "我的邮箱是sensitive@example.com", timestamp: "2026-07-12" }]);
  const sensitiveIndex = 1;
  await controller.createCandidate(sensitiveIndex);

  // Assert sensitive candidate exists
  assert.equal(controller.candidates[sensitiveIndex].isSensitive, true);

  // Step 1: Prepare sensitive candidate
  const prepared = await controller.prepareCandidate(sensitiveIndex);
  assert.ok(prepared);
  assert.equal(calls.prepareCandidate.length, 1);

  // Step 2: Confirm sensitive candidate with token
  await controller.confirmCandidate(sensitiveIndex, prepared!.approvalToken);

  // Confirm call made
  assert.equal(calls.confirmCandidate.length, 1);
  assert.equal(controller.candidates[sensitiveIndex].state, "confirmed");
});

test("3. lifeId 在所有操作中被正确传递", async () => {
  const { calls, mockMemoryService, mockMemoryExtractor, mockConfirmationService } = createMocks();
  const controller = new MemoryReviewController(mockMemoryService, mockMemoryExtractor, mockConfirmationService);
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

  // 3. Prepare + Confirm (two-phase)
  const prepared = await controller.prepareCandidate(0);
  assert.ok(prepared);
  await controller.confirmCandidate(0, prepared!.approvalToken);
  assert.equal(calls.confirmCandidate.length, 1);

  // Re-extract and delete candidate
  await controller.extract([{ role: "user", content: "我喜欢乌龙茶", timestamp: "2026-07-12" }]);
  await controller.createCandidate(0);
  await controller.deleteCandidate(0);
  assert.equal(calls.deleteCalls.length, 1);
  assert.equal(calls.deleteCalls[0].lifeId, "life-secure-id");
});

test("4. 错误的候选数据生命ID不能覆盖 Controller 使用的当前 lifeId", async () => {
  const { calls, mockMemoryService, mockMemoryExtractor, mockConfirmationService } = createMocks();
  const controller = new MemoryReviewController(mockMemoryService, mockMemoryExtractor, mockConfirmationService);
  controller.setLifeId("life-correct");

  await controller.extract([{ role: "user", content: "我喜欢乌龙茶", timestamp: "2026-07-12" }]);

  // Attempt to modify the in-memory lifeId directly on the candidate object (simulating cross-life compromise)
  const candidate = controller.candidates[0];
  const candidateRef = candidate as { lifeId?: string };
  candidateRef.lifeId = "life-malicious";

  // Create call must use the controller's active lifeId
  await controller.createCandidate(0);
  assert.equal(calls.createCandidate.length, 1);
  assert.equal(calls.createCandidate[0].lifeId, "life-correct");
});

test("5. Delete Mock 与失败恢复测试", async () => {
  const { calls, mockMemoryService, mockMemoryExtractor, mockConfirmationService } = createMocks();
  mockMemoryService.delete = async () => {
    throw new Error("Simulated SQLite delete failure");
  };

  const controller = new MemoryReviewController(mockMemoryService, mockMemoryExtractor, mockConfirmationService);
  controller.setLifeId("life-correct");

  await controller.extract([{ role: "user", content: "我喜欢乌龙茶", timestamp: "2026-07-12" }]);
  await controller.createCandidate(0);

  const beforeId = controller.candidates[0].dbRecord?.id;
  assert.ok(beforeId);
  assert.equal(controller.candidates[0].state, "candidateCreated");

  // Attempt deletion which fails
  await controller.deleteCandidate(0);

  // Deletion calls track count = 0 since it threw error, but we assert state restoration
  assert.equal(calls.deleteCalls.length, 0);

  // Assert candidate remains in list, original state restored, memoryId kept, error code captured
  assert.equal(controller.candidates.length, 2);
  assert.equal(controller.candidates[0].state, "candidateCreated");
  assert.equal(controller.candidates[0].dbRecord?.id, beforeId);
  assert.equal(controller.candidates[0].error?.stage, "deletion");
  assert.equal(controller.candidates[0].error?.code, "MEMORY_ERROR");
});

test("6. closeReviewPanel 清理草稿并检测未确认候选", async () => {
  const { calls, mockMemoryService, mockMemoryExtractor, mockConfirmationService } = createMocks();
  const controller = new MemoryReviewController(mockMemoryService, mockMemoryExtractor, mockConfirmationService);
  controller.setLifeId("life-123");

  await controller.extract([{ role: "user", content: "我喜欢乌龙茶", timestamp: "2026-07-12" }]);
  await controller.createCandidate(0);

  // First candidate index 0 is candidateCreated (saved in DB, not confirmed)
  // Second candidate index 1 is draft
  assert.equal(controller.candidates.length, 2);

  const hasUnconfirmed = controller.closeReviewPanel();

  // Draft index 1 cleared, saved candidate remains
  assert.equal(controller.candidates.length, 1);
  assert.equal(controller.candidates[0].state, "candidateCreated");
  assert.equal(hasUnconfirmed, true); // True since unconfirmed saved candidates exist
  assert.equal(calls.deleteCalls.length, 0); // No delete called on closing
});

test("7. confirmed 状态 Controller 拒绝编辑和更新", async () => {
  const { calls, mockMemoryService, mockMemoryExtractor, mockConfirmationService } = createMocks();
  const controller = new MemoryReviewController(mockMemoryService, mockMemoryExtractor, mockConfirmationService);
  controller.setLifeId("life-123");

  await controller.extract([{ role: "user", content: "我喜欢乌龙茶", timestamp: "2026-07-12" }]);
  await controller.createCandidate(0);

  // Prepare and confirm
  const prepared = await controller.prepareCandidate(0);
  assert.ok(prepared);
  await controller.confirmCandidate(0, prepared!.approvalToken);

  assert.equal(controller.candidates[0].state, "confirmed");

  // Edit rejected
  controller.editCandidate(0, "experience", "edited content", "edited summary");
  assert.equal(controller.candidates[0].content, "我喜欢乌龙茶");

  // Update rejected
  await controller.updateCandidate(0);
  assert.equal(calls.updateCandidate.length, 0);
  assert.equal(controller.candidates[0].error?.code, "CONFIRMED_LOCK");
});

test("8. 创建守卫失败不影响其他候选", async () => {
  const { mockMemoryService, mockMemoryExtractor, mockConfirmationService } = createMocks();
  const controller = new MemoryReviewController(mockMemoryService, mockMemoryExtractor, mockConfirmationService);
  controller.setLifeId("life-123");

  await controller.extract([{ role: "user", content: "我喜欢乌龙茶", timestamp: "2026-07-12" }]);

  // Simulate first candidate violating draft state guard
  controller.candidates[0].state = "creatingCandidate";

  // Create fails on index 0
  await controller.createCandidate(0);
  assert.equal(controller.candidates[0].error?.code, "INVALID_STATE");

  // Index 1 remains draft and unaffected
  assert.equal(controller.candidates[1].state, "draft");
  await controller.createCandidate(1);
  assert.equal(controller.candidates[1].state, "candidateCreated");
});

test("9. Adapter 与 ChatView 实际关闭路径绑定验证", () => {
  const { mockMemoryService, mockMemoryExtractor, mockConfirmationService } = createMocks();
  const controller = new MemoryReviewController(mockMemoryService, mockMemoryExtractor, mockConfirmationService);
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

  // Triggering the adapter handler
  handleClosePanel();

  // Asserts panel closes and sets persistent warning ref correctly
  assert.equal(actions.showMemoryPanel.value, false);
  assert.equal(actions.showUnconfirmedHint.value, true);

  // Validate ChatView.vue source binding
  const chatViewPath = path.resolve(__dirname, "../src/chat/ChatView.vue");
  const chatViewContent = fs.readFileSync(chatViewPath, "utf8");

  // Backdrop overlay must call handleClosePanel
  assert.ok(
    chatViewContent.includes('class="memory-panel-backdrop" @click="handleClosePanel"')
  );

  // Drawer close button must call handleClosePanel
  assert.ok(
    chatViewContent.includes('class="close-btn" type="button" @click="handleClosePanel"')
  );
});
