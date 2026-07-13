import {
  memoryManagementService,
  type IMemoryManagementService,
  type ManagedMemory,
  type ManagedMemoryDetail,
  type MemoryKind,
  type MemoryListCursor,
  type MemoryListRequest,
  type MemoryRevision,
  type MemoryStatus,
  type UpdateConfirmedMemoryRequest,
  type SetMemorySensitiveRequest,
  type DeleteMemoryRequest,
  type MemoryManagementErrorCode,
} from "./index.ts";

export type MemoryCenterPhase =
  | "idle"
  | "loading"
  | "loadingDetail"
  | "loadingRevisions"
  | "saving"
  | "settingSensitive"
  | "deleting"
  | "succeeded"
  | "failed";

export type MemoryCenterOperation =
  | "list"
  | "getDetail"
  | "loadRevisions"
  | "update"
  | "setSensitive"
  | "delete";

export interface MemoryCenterError {
  code: MemoryManagementErrorCode | "MEMORY_CENTER_ERROR";
  message: string;
  operation: MemoryCenterOperation;
  recoverable: boolean;
}

export interface MemoryFilterState {
  status: MemoryStatus | "all";
  kind: MemoryKind | "all";
  sensitive: boolean | undefined;
  query: string;
}

export interface MemoryEditDraft {
  kind: MemoryKind;
  content: string;
  summary: string;
}

const PAGE_SIZE = 20;

export class MemoryCenterController {
  // List state
  memories: ManagedMemory[] = [];
  nextCursor: MemoryListCursor | null = null;
  listPhase: MemoryCenterPhase = "idle";
  listError?: MemoryCenterError;
  hasMore = false;
  isLoadingMore = false;

  // Detail state
  selectedMemoryId: string | null = null;
  detail: ManagedMemoryDetail | null = null;
  detailPhase: MemoryCenterPhase = "idle";
  detailError?: MemoryCenterError;

  // Revision state
  revisions: MemoryRevision[] = [];
  revisionPhase: MemoryCenterPhase = "idle";
  revisionError?: MemoryCenterError;

  // Edit state
  editDraft: MemoryEditDraft | null = null;
  editPhase: MemoryCenterPhase = "idle";
  editError?: MemoryCenterError;
  editConflictLatest: ManagedMemoryDetail | null = null;

  // Delete state
  deletePhase: MemoryCenterPhase = "idle";
  deleteError?: MemoryCenterError;
  deleteConfirmVisible = false;

  // Sensitive state
  sensitivePhase: MemoryCenterPhase = "idle";
  sensitiveError?: MemoryCenterError;

  // Filter state
  filters: MemoryFilterState = {
    status: "all",
    kind: "all",
    sensitive: undefined,
    query: "",
  };

  // Stale request guard
  detailRequestSeq = 0;
  listRequestSeq = 0;

  readonly service: IMemoryManagementService;

  constructor(service: IMemoryManagementService = memoryManagementService) {
    this.service = service;
  }

  // ─── List Operations ───

  async refreshList(): Promise<void> {
    const seq = ++this.listRequestSeq;
    this.listPhase = "loading";
    this.listError = undefined;
    this.memories = [];
    this.nextCursor = null;
    this.hasMore = false;

    try {
      const result = await this.service.list(this.buildListRequest());
      if (seq !== this.listRequestSeq) {
        return;
      }
      this.memories = result.items;
      this.nextCursor = result.nextCursor;
      this.hasMore = result.nextCursor !== null;
      this.listPhase = "succeeded";
    } catch (caught: unknown) {
      if (seq !== this.listRequestSeq) {
        return;
      }
      this.listPhase = "failed";
      this.listError = toCenterError(caught, "list");
    }
  }

  async loadMore(): Promise<void> {
    if (!this.hasMore || this.isLoadingMore || !this.nextCursor) {
      return;
    }
    const seq = this.listRequestSeq;
    this.isLoadingMore = true;
    try {
      const request = this.buildListRequest();
      request.cursor = this.nextCursor;
      const result = await this.service.list(request);
      if (seq !== this.listRequestSeq) {
        return;
      }
      this.memories = [...this.memories, ...result.items];
      this.nextCursor = result.nextCursor;
      this.hasMore = result.nextCursor !== null;
    } catch (caught: unknown) {
      if (seq !== this.listRequestSeq) {
        return;
      }
      this.listError = toCenterError(caught, "list");
    } finally {
      if (seq === this.listRequestSeq) {
        this.isLoadingMore = false;
      }
    }
  }

  updateFilters(partial: Partial<MemoryFilterState>): void {
    Object.assign(this.filters, partial);
    void this.refreshList();
  }

  // ─── Detail Operations ───

  async selectMemory(memoryId: string): Promise<void> {
    const seq = ++this.detailRequestSeq;
    this.selectedMemoryId = memoryId;
    this.detailPhase = "loadingDetail";
    this.detailError = undefined;
    this.detail = null;
    this.revisions = [];
    this.revisionPhase = "idle";
    this.editConflictLatest = null;
    this.closeEditForm();
    this.closeDeleteConfirm();

    try {
      const result = await this.service.get(memoryId);
      if (seq !== this.detailRequestSeq) {
        return;
      }
      this.detail = result;
      this.detailPhase = "succeeded";
    } catch (caught: unknown) {
      if (seq !== this.detailRequestSeq) {
        return;
      }
      this.detailPhase = "failed";
      this.detailError = toCenterError(caught, "getDetail");
    }
  }

  clearSelection(): void {
    this.selectedMemoryId = null;
    this.detail = null;
    this.detailPhase = "idle";
    this.detailError = undefined;
    this.revisions = [];
    this.revisionPhase = "idle";
    this.revisionError = undefined;
    this.editConflictLatest = null;
    this.closeEditForm();
    this.closeDeleteConfirm();
  }

  // ─── Revision Operations ───

  async loadRevisions(): Promise<void> {
    if (!this.selectedMemoryId) {
      return;
    }
    const seq = this.detailRequestSeq;
    this.revisionPhase = "loadingRevisions";
    this.revisionError = undefined;

    try {
      const result = await this.service.listRevisions(this.selectedMemoryId);
      if (seq !== this.detailRequestSeq) {
        return;
      }
      this.revisions = result;
      this.revisionPhase = "succeeded";
    } catch (caught: unknown) {
      if (seq !== this.detailRequestSeq) {
        return;
      }
      this.revisionPhase = "failed";
      this.revisionError = toCenterError(caught, "loadRevisions");
    }
  }

  // ─── Edit Operations ───

  openEditForm(): void {
    if (!this.detail) {
      return;
    }
    this.editDraft = {
      kind: this.detail.kind,
      content: this.detail.content,
      summary: this.detail.summary ?? "",
    };
    this.editPhase = "idle";
    this.editError = undefined;
    this.editConflictLatest = null;
  }

  closeEditForm(): void {
    this.editDraft = null;
    this.editPhase = "idle";
    this.editError = undefined;
    this.editConflictLatest = null;
  }

  async saveEdit(): Promise<boolean> {
    if (!this.detail || !this.editDraft) {
      return false;
    }

    const content = this.editDraft.content.trim();
    if (content.length === 0) {
      this.editPhase = "failed";
      this.editError = {
        code: "INVALID_MEMORY_CONTENT",
        message: "Memory content cannot be empty.",
        operation: "update",
        recoverable: true,
      };
      return false;
    }

    const summary = this.editDraft.summary.trim() || null;

    if (
      content === this.detail.content &&
      this.editDraft.kind === this.detail.kind &&
      summary === (this.detail.summary ?? null)
    ) {
      this.editDraft = null;
      this.editPhase = "succeeded";
      return true;
    }

    this.editPhase = "saving";
    this.editError = undefined;
    this.editConflictLatest = null;

    const request: UpdateConfirmedMemoryRequest = {
      memoryId: this.detail.id,
      expectedRevision: this.detail.revision,
      kind: this.editDraft.kind,
      content,
      summary,
    };

    try {
      const updated = await this.service.update(request);
      this.detail = updated;
      this.editDraft = null;
      this.editPhase = "succeeded";
      await this.refreshList();
      if (this.revisionPhase === "succeeded") {
        await this.loadRevisions();
      }
      return true;
    } catch (caught: unknown) {
      this.editPhase = "failed";
      this.editError = toCenterError(caught, "update");

      if (isRevisionConflict(caught)) {
        await this.handleRevisionConflict();
      }
      return false;
    }
  }

  async handleRevisionConflict(): Promise<void> {
    if (!this.selectedMemoryId) {
      return;
    }
    try {
      this.editConflictLatest = await this.service.get(this.selectedMemoryId);
      // Preserve user draft - do not overwrite
    } catch {
      // If we can't fetch latest, user still has their draft
    }
  }

  acceptConflictResolution(): void {
    if (this.editConflictLatest) {
      this.detail = this.editConflictLatest;
      this.editConflictLatest = null;
      if (this.editDraft) {
        this.editDraft = {
          kind: this.detail.kind,
          content: this.detail.content,
          summary: this.detail.summary ?? "",
        };
      }
      this.editError = undefined;
      this.editPhase = "idle";
    }
  }

  // ─── Sensitive Toggle ───

  async toggleSensitive(): Promise<boolean> {
    if (!this.detail) {
      return false;
    }

    this.sensitivePhase = "settingSensitive";
    this.sensitiveError = undefined;

    const request: SetMemorySensitiveRequest = {
      memoryId: this.detail.id,
      expectedRevision: this.detail.revision,
      isSensitive: !this.detail.isSensitive,
    };

    try {
      const updated = await this.service.setSensitive(request);
      this.detail = updated;
      this.sensitivePhase = "succeeded";
      await this.refreshList();
      if (this.revisionPhase === "succeeded") {
        await this.loadRevisions();
      }
      return true;
    } catch (caught: unknown) {
      this.sensitivePhase = "failed";
      this.sensitiveError = toCenterError(caught, "setSensitive");
      return false;
    }
  }

  // ─── Delete Operations ───

  openDeleteConfirm(): void {
    this.deleteConfirmVisible = true;
    this.deletePhase = "idle";
    this.deleteError = undefined;
  }

  closeDeleteConfirm(): void {
    this.deleteConfirmVisible = false;
    this.deletePhase = "idle";
    this.deleteError = undefined;
  }

  async confirmDelete(): Promise<boolean> {
    if (!this.detail) {
      return false;
    }

    this.deletePhase = "deleting";
    this.deleteError = undefined;

    const request: DeleteMemoryRequest = {
      memoryId: this.detail.id,
      expectedRevision: this.detail.revision,
    };

    try {
      await this.service.deletePermanently(request);
      this.deletePhase = "succeeded";
      this.deleteConfirmVisible = false;
      this.clearSelection();
      await this.refreshList();
      return true;
    } catch (caught: unknown) {
      this.deletePhase = "failed";
      this.deleteError = toCenterError(caught, "delete");
      return false;
    }
  }

  // ─── Helpers ───

  buildListRequest(): MemoryListRequest {
    const request: MemoryListRequest = { pageSize: PAGE_SIZE };
    if (this.filters.status !== "all") {
      request.status = this.filters.status;
    }
    if (this.filters.kind !== "all") {
      request.kind = this.filters.kind;
    }
    if (this.filters.sensitive !== undefined) {
      request.sensitive = this.filters.sensitive;
    }
    if (this.filters.query.trim().length > 0) {
      request.query = this.filters.query.trim();
    }
    return request;
  }
}

function toCenterError(
  caught: unknown,
  operation: MemoryCenterOperation,
): MemoryCenterError {
  if (isErrorRecord(caught)) {
    const code =
      typeof caught.code === "string"
        ? (caught.code as MemoryManagementErrorCode)
        : "MEMORY_CENTER_ERROR";
    const message =
      typeof caught.message === "string"
        ? caught.message
        : "An unexpected error occurred.";
    const recoverable =
      typeof caught.recoverable === "boolean" ? caught.recoverable : true;
    return { code, message, operation, recoverable };
  }
  return {
    code: "MEMORY_CENTER_ERROR",
    message: "An unexpected error occurred.",
    operation,
    recoverable: true,
  };
}

function isErrorRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isRevisionConflict(caught: unknown): boolean {
  return (
    isErrorRecord(caught) &&
    caught.code === "MEMORY_REVISION_CONFLICT"
  );
}
