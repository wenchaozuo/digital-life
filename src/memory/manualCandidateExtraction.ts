import { invoke } from "@tauri-apps/api/core";

export type ExtractionTriggerStatus =
  | "completed"
  | "processing"
  | "retry_wait"
  | "failed"
  | "snapshot_invalidated"
  | "no_eligible_snapshot"
  | "stale_or_conflict";

export interface ExtractionTriggerResponse {
  status: ExtractionTriggerStatus;
  createdCount?: number;
  mergedEvidenceCount?: number;
  blockedCount?: number;
  safeMessageCode: string;
}

const statuses = new Set<ExtractionTriggerStatus>([
  "completed",
  "processing",
  "retry_wait",
  "failed",
  "snapshot_invalidated",
  "no_eligible_snapshot",
  "stale_or_conflict",
]);

export class ManualCandidateExtractionService {
  private readonly invokeFn: <T>(command: string, args?: Record<string, unknown>) => Promise<T>;

  constructor(
    invokeFn: <T>(command: string, args?: Record<string, unknown>) => Promise<T> = invoke,
  ) {
    this.invokeFn = invokeFn;
  }

  async trigger(lifeId: string, conversationId: string): Promise<ExtractionTriggerResponse> {
    if (!lifeId || !conversationId) {
      throw new Error("A current life and conversation are required.");
    }
    const raw = await this.invokeFn<unknown>("extract_candidate_memories", { lifeId, conversationId });
    return parseExtractionTriggerResponse(raw);
  }
}

export function parseExtractionTriggerResponse(value: unknown): ExtractionTriggerResponse {
  if (!isRecord(value) || typeof value.status !== "string" || !statuses.has(value.status as ExtractionTriggerStatus)) {
    throw new Error("Candidate memory extraction returned an invalid response.");
  }
  if (typeof value.safeMessageCode !== "string") {
    throw new Error("Candidate memory extraction returned an invalid response.");
  }
  return {
    status: value.status as ExtractionTriggerStatus,
    createdCount: numberOrUndefined(value.createdCount),
    mergedEvidenceCount: numberOrUndefined(value.mergedEvidenceCount),
    blockedCount: numberOrUndefined(value.blockedCount),
    safeMessageCode: value.safeMessageCode,
  };
}

export function extractionStatusMessage(response: ExtractionTriggerResponse): string {
  switch (response.status) {
    case "completed":
      if ((response.createdCount ?? 0) === 0 && (response.mergedEvidenceCount ?? 0) === 0) {
        return "当前对话没有发现可提取内容。";
      }
      return `已创建 ${response.createdCount ?? 0} 条候选记忆，已合并 ${response.mergedEvidenceCount ?? 0} 条候选证据。`;
    case "processing":
      return "该对话正在提取候选记忆。";
    case "retry_wait":
      return "本次提取暂未完成，请稍后手动重试。";
    case "snapshot_invalidated":
      return "对话内容已发生变化，请重新触发。";
    case "no_eligible_snapshot":
      return "当前对话还没有可提取的完整用户消息。";
    case "stale_or_conflict":
      return "本次提取未完成，请重新触发。";
    case "failed":
      return "候选记忆提取未完成，请稍后手动重试。";
  }
}

function numberOrUndefined(value: unknown): number | undefined {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 ? value : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

export const manualCandidateExtractionService = new ManualCandidateExtractionService();
