import type {
  MemoryRecord,
  CreateMemoryCandidateRequest,
  UpdateMemoryRequest,
  DeleteMemoryResult,
  MemoryKind,
  MemorySourceType,
} from "../memory/types";
import type { MemoryExtractionResult } from "../memory/extractor/types";

// ── Confirmation Actions Interface ────────────────────────────────────
// Controller depends on this interface, not on Pinia directly.
// The production implementation is provided by the Pinia Store.

export interface CandidateConfirmationActions {
  prepare(candidateId: string): Promise<void>;
  confirm(): Promise<void>;
  cancel(): Promise<void>;
  clearCandidateConfirmation(): void;
  readonly canPrepare: boolean;
  readonly canConfirm: boolean;
  readonly canCancel: boolean;
}

// ── Types ─────────────────────────────────────────────────────────────

export type PanelState = "idle" | "extracting" | "empty" | "reviewing" | "failed";

export type CandidateState =
  | "draft"
  | "creatingCandidate"
  | "candidateCreated"
  | "updating"
  | "confirming"
  | "confirmed"
  | "deleting";

export interface UiCandidate {
  id: string;
  kind: MemoryKind;
  content: string;
  summary: string;
  importance: number;
  confidence: number;
  isSensitive: boolean;
  sourceType: MemorySourceType;
  sourceCreatedAt: string;

  sensitiveConsentChecked: boolean;
  state: CandidateState;
  dbRecord?: MemoryRecord;
  error?: {
    code: string;
    message: string;
    stage: "creation" | "update" | "confirmation" | "deletion";
  };
}

export interface IMemoryService {
  createCandidate(request: CreateMemoryCandidateRequest): Promise<MemoryRecord>;
  updateCandidate(request: UpdateMemoryRequest): Promise<MemoryRecord>;
  delete(lifeId: string, memoryId: string): Promise<DeleteMemoryResult>;
}

export interface IMemoryExtractor {
  extract(request: {
    lifeId: string;
    messages: readonly { role: string; content: string; timestamp: string }[];
    sourceType: MemorySourceType;
  }): MemoryExtractionResult;
}

interface ErrorWithCode {
  code: string;
}

function hasCode(err: unknown): err is ErrorWithCode {
  return (
    typeof err === "object" &&
    err !== null &&
    "code" in err &&
    typeof (err as Record<string, unknown>).code === "string"
  );
}

export class MemoryReviewController {
  panelState: PanelState = "idle";
  candidates: UiCandidate[] = [];
  lifeId = "";
  error: { code: string; message: string; stage?: string } | null = null;

  private memoryService: IMemoryService;
  private memoryExtractor: IMemoryExtractor;
  private confirmationActions: CandidateConfirmationActions;

  constructor(
    memoryService: IMemoryService,
    memoryExtractor: IMemoryExtractor,
    confirmationActions: CandidateConfirmationActions,
  ) {
    this.memoryService = memoryService;
    this.memoryExtractor = memoryExtractor;
    this.confirmationActions = confirmationActions;
  }

  setLifeId(lifeId: string): void {
    this.lifeId = lifeId;
  }

  async extract(messages: readonly { role: string; content: string; timestamp: string }[]): Promise<void> {
    if (!this.lifeId) {
      this.panelState = "failed";
      this.error = {
        code: "LIFE_ID_REQUIRED",
        message: "No current life identity is active.",
        stage: "extraction",
      };
      return;
    }

    this.panelState = "extracting";
    this.error = null;

    try {
      const result = this.memoryExtractor.extract({
        lifeId: this.lifeId,
        messages,
        sourceType: "conversation",
      });

      if (result.candidates.length === 0) {
        this.panelState = "empty";
        this.candidates = [];
      } else {
        this.candidates = result.candidates.map((c, index) => ({
          id: `candidate-${Date.now()}-${index}-${Math.random().toString(36).substring(2, 9)}`,
          kind: c.kind,
          content: c.content,
          summary: c.summary || "",
          importance: c.importance,
          confidence: c.confidence,
          isSensitive: c.isSensitive,
          sourceType: c.sourceType,
          sourceCreatedAt: c.sourceCreatedAt,
          sensitiveConsentChecked: false,
          state: "draft",
        }));
        this.panelState = "reviewing";
      }
    } catch (err: unknown) {
      this.panelState = "failed";
      this.error = {
        code: "EXTRACTION_FAILED",
        message: err instanceof Error ? err.message : "Memory extraction failed.",
        stage: "extraction",
      };
    }
  }

  editCandidate(index: number, kind: MemoryKind, content: string, summary: string): void {
    const candidate = this.candidates[index];
    if (!candidate || candidate.state === "confirmed") {
      return;
    }
    candidate.kind = kind;
    candidate.content = content;
    candidate.summary = summary;
  }

  async createCandidate(index: number): Promise<void> {
    const candidate = this.candidates[index];
    if (!candidate) {
      return;
    }

    if (
      candidate.state !== "draft" ||
      (candidate.dbRecord !== undefined && candidate.dbRecord.id.length > 0)
    ) {
      candidate.error = {
        code: "INVALID_STATE",
        message: "Cannot create a memory candidate from this state.",
        stage: "creation",
      };
      return;
    }

    candidate.state = "creatingCandidate";
    candidate.error = undefined;

    try {
      const request: CreateMemoryCandidateRequest = {
        lifeId: this.lifeId,
        kind: candidate.kind,
        content: candidate.content,
        summary: candidate.summary || undefined,
        sourceType: candidate.sourceType,
        sourceCreatedAt: candidate.sourceCreatedAt,
        importance: candidate.importance,
        confidence: candidate.confidence,
        isSensitive: candidate.isSensitive,
      };

      const record = await this.memoryService.createCandidate(request);
      candidate.dbRecord = record;
      candidate.kind = record.kind;
      candidate.content = record.content;
      candidate.summary = record.summary || "";
      candidate.isSensitive = record.isSensitive;
      candidate.state = "candidateCreated";
    } catch (err: unknown) {
      candidate.state = "draft";
      candidate.error = {
        code: getErrorCode(err),
        message: getErrorMessage(err),
        stage: "creation",
      };
    }
  }

  async updateCandidate(index: number): Promise<void> {
    const candidate = this.candidates[index];
    if (!candidate) {
      return;
    }

    if (candidate.state === "confirmed") {
      candidate.error = {
        code: "CONFIRMED_LOCK",
        message: "Confirmed memories cannot be modified.",
        stage: "update",
      };
      return;
    }

    if (!candidate.dbRecord || !candidate.dbRecord.id) {
      candidate.error = {
        code: "MISSING_ID",
        message: "Cannot update a candidate that has not been saved.",
        stage: "update",
      };
      return;
    }

    candidate.state = "updating";
    candidate.error = undefined;

    try {
      const request: UpdateMemoryRequest = {
        lifeId: this.lifeId,
        memoryId: candidate.dbRecord.id,
        kind: candidate.kind,
        content: candidate.content,
        summary: candidate.summary || undefined,
        sourceType: candidate.sourceType,
        sourceCreatedAt: candidate.sourceCreatedAt,
        importance: candidate.importance,
        confidence: candidate.confidence,
        isSensitive: candidate.isSensitive,
      };

      const record = await this.memoryService.updateCandidate(request);
      candidate.dbRecord = record;
      candidate.kind = record.kind;
      candidate.content = record.content;
      candidate.summary = record.summary || "";
      candidate.state = "candidateCreated";
    } catch (err: unknown) {
      candidate.state = "candidateCreated";
      candidate.error = {
        code: getErrorCode(err),
        message: getErrorMessage(err),
        stage: "update",
      };
    }
  }

  /**
   * Prepare a candidate for confirmation via the Store.
   * Controller does NOT receive or handle tokens.
   */
  async prepareCandidate(index: number): Promise<void> {
    const candidate = this.candidates[index];
    if (!candidate) return;
    if (candidate.state === "confirmed") return;
    if (!candidate.dbRecord?.id) {
      candidate.error = {
        code: "MISSING_ID",
        message: "Cannot prepare a candidate that has not been saved.",
        stage: "confirmation",
      };
      return;
    }

    candidate.error = undefined;

    try {
      await this.confirmationActions.prepare(candidate.dbRecord.id);
    } catch (err: unknown) {
      candidate.error = {
        code: getErrorCode(err),
        message: getErrorMessage(err),
        stage: "confirmation",
      };
    }
  }

  /**
   * Confirm the currently prepared candidate via the Store.
   * Token is managed internally by the Store.
   */
  async confirmPreparedCandidate(): Promise<void> {
    try {
      await this.confirmationActions.confirm();
    } catch {
      // Store handles error state internally
    }
  }

  /**
   * Cancel the currently prepared candidate via the Store.
   */
  async cancelPreparedCandidate(): Promise<void> {
    try {
      await this.confirmationActions.cancel();
    } catch {
      // Store handles error state internally
    }
  }

  async deleteCandidate(index: number): Promise<void> {
    const candidate = this.candidates[index];
    if (!candidate) {
      return;
    }

    if (candidate.dbRecord) {
      const originalState = candidate.state;
      candidate.state = "deleting";
      candidate.error = undefined;
      try {
        await this.memoryService.delete(this.lifeId, candidate.dbRecord.id);
        this.removeCandidateAt(index);
      } catch (err: unknown) {
        candidate.state = originalState;
        candidate.error = {
          code: getErrorCode(err),
          message: getErrorMessage(err),
          stage: "deletion",
        };
      }
    } else {
      this.removeCandidateAt(index);
    }
  }

  discardDraft(index: number): void {
    const candidate = this.candidates[index];
    if (candidate && !candidate.dbRecord) {
      this.removeCandidateAt(index);
    }
  }

  closeReviewPanel(): boolean {
    this.candidates = this.candidates.filter((c) => c.dbRecord !== undefined);
    const hasUnconfirmed = this.candidates.some((c) => c.state !== "confirmed");
    this.panelState = "idle";
    return hasUnconfirmed;
  }

  private removeCandidateAt(index: number): void {
    this.candidates.splice(index, 1);
    if (this.candidates.length === 0) {
      this.panelState = "empty";
    }
  }

  isModified(index: number): boolean {
    const candidate = this.candidates[index];
    if (!candidate || !candidate.dbRecord) {
      return false;
    }
    return (
      candidate.kind !== candidate.dbRecord.kind ||
      candidate.content !== candidate.dbRecord.content ||
      candidate.summary !== candidate.dbRecord.summary
    );
  }
}

function getErrorCode(err: unknown): string {
  if (hasCode(err)) {
    return err.code;
  }
  return "MEMORY_ERROR";
}

function getErrorMessage(err: unknown): string {
  if (err instanceof Error) {
    const msg = err.message;
    if (msg.includes("SQLITE") || msg.includes("database") || msg.includes("\\") || msg.includes("/")) {
      return "The memory operation could not be completed.";
    }
    return msg;
  }
  return "The memory operation could not be completed.";
}
