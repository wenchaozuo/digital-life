import assert from "node:assert/strict";
import test from "node:test";
import {
  extractionStatusMessage,
  ManualCandidateExtractionService,
  parseExtractionTriggerResponse,
} from "../src/memory/manualCandidateExtraction.ts";

test("manual trigger sends only current life and conversation identifiers once", async () => {
  const calls: Array<{ command: string; args?: Record<string, unknown> }> = [];
  const service = new ManualCandidateExtractionService(async (command, args) => {
    calls.push({ command, args });
    return { status: "completed", createdCount: 2, mergedEvidenceCount: 1, blockedCount: 0, safeMessageCode: "CANDIDATE_EXTRACTION_COMPLETED" };
  });
  const response = await service.trigger("life-1", "conversation-1");
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0], { command: "extract_candidate_memories", args: { lifeId: "life-1", conversationId: "conversation-1" } });
  assert.equal(extractionStatusMessage(response), "已创建 2 条候选记忆，已合并 1 条候选证据。");
});

test("manual trigger maps every safe status without rendering internal fields", () => {
  const statuses = ["processing", "retry_wait", "failed", "snapshot_invalidated", "no_eligible_snapshot", "stale_or_conflict"] as const;
  for (const status of statuses) {
    const message = extractionStatusMessage(parseExtractionTriggerResponse({ status, safeMessageCode: "SAFE" }));
    assert.ok(message.length > 0);
    assert.ok(!message.includes("run_id"));
    assert.ok(!message.includes("token"));
  }
});
