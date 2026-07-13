<script setup lang="ts">
import { ref, watch } from "vue";
import type { MemoryCenterController } from "./memoryCenterController.ts";
import type { MemoryKind } from "./types.ts";

const props = defineProps<{ controller: MemoryCenterController }>();

const showRevisions = ref(false);

function formatTimestamp(ts: string): string {
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

function changeTypeLabel(changeType: string): string {
  switch (changeType) {
    case "confirmed": return "Confirmed";
    case "edited": return "Edited";
    case "sensitivity_changed": return "Sensitivity changed";
    default: return changeType;
  }
}

function onKindChange(event: Event): void {
  if (props.controller.editDraft) {
    props.controller.editDraft.kind = (event.target as HTMLSelectElement).value as MemoryKind;
  }
}

function onContentInput(event: Event): void {
  if (props.controller.editDraft) {
    props.controller.editDraft.content = (event.target as HTMLInputElement).value;
  }
}

function onSummaryInput(event: Event): void {
  if (props.controller.editDraft) {
    props.controller.editDraft.summary = (event.target as HTMLInputElement).value;
  }
}

async function toggleRevisions(): Promise<void> {
  showRevisions.value = !showRevisions.value;
  if (showRevisions.value && props.controller.revisions.length === 0) {
    await props.controller.loadRevisions();
  }
}

// Reset revision panel when selection changes
watch(
  () => props.controller.selectedMemoryId,
  () => {
    showRevisions.value = false;
  },
);

const kindOptions: MemoryKind[] = [
  "experience",
  "preference",
  "fact",
  "relationship",
  "goal",
  "skill",
  "other",
];
</script>

<template>
  <section class="memory-detail-panel" aria-label="Memory detail">
    <!-- No selection -->
    <div v-if="!controller.selectedMemoryId" class="empty-state">
      <strong>Select a memory</strong>
      <p>Choose a memory from the list to view its details.</p>
    </div>

    <!-- Loading detail -->
    <div v-else-if="controller.detailPhase === 'loadingDetail'" class="empty-state">
      Loading memory detail…
    </div>

    <!-- Detail load failed -->
    <div
      v-else-if="controller.detailPhase === 'failed'"
      class="empty-state error"
      role="alert"
    >
      <strong>{{ controller.detailError?.code }}</strong>
      <p>{{ controller.detailError?.message }}</p>
      <button type="button" @click="controller.selectMemory(controller.selectedMemoryId!)">
        Retry
      </button>
    </div>

    <!-- Detail loaded -->
    <div v-else-if="controller.detail" class="detail-content">
      <!-- Header -->
      <div class="detail-header">
        <div class="detail-badges">
          <span class="kind-badge">{{ controller.detail.kind }}</span>
          <span class="status-badge" :class="`status-${controller.detail.status}`">
            {{ controller.detail.status }}
          </span>
          <span v-if="controller.detail.isSensitive" class="sensitive-badge">sensitive</span>
        </div>
        <span class="revision-info">Revision {{ controller.detail.revision }}</span>
      </div>

      <!-- Edit form or read-only view -->
      <div v-if="controller.editDraft" class="edit-form">
        <h3>Edit Memory</h3>

        <label class="field-label">
          Kind
          <select :value="controller.editDraft.kind" @change="onKindChange">
            <option v-for="k in kindOptions" :key="k" :value="k">{{ k }}</option>
          </select>
        </label>

        <label class="field-label">
          Content
          <textarea
            :value="controller.editDraft.content"
            rows="4"
            @input="onContentInput"
          ></textarea>
        </label>

        <label class="field-label">
          Summary
          <input
            type="text"
            :value="controller.editDraft.summary"
            placeholder="(optional summary)"
            @input="onSummaryInput"
          />
        </label>

        <!-- Conflict resolution -->
        <div v-if="controller.editError?.code === 'MEMORY_REVISION_CONFLICT'" class="conflict-banner">
          <strong>Revision Conflict</strong>
          <p>
            This memory was modified by another operation. Your draft has been preserved.
            The latest server version is shown below — review and save again.
          </p>
          <div v-if="controller.editConflictLatest" class="conflict-latest">
            <p><strong>Server version (rev {{ controller.editConflictLatest.revision }}):</strong></p>
            <p class="conflict-content">{{ controller.editConflictLatest.content }}</p>
            <p v-if="controller.editConflictLatest.summary">
              <em>Summary:</em> {{ controller.editConflictLatest.summary }}
            </p>
          </div>
          <button type="button" @click="controller.acceptConflictResolution()">
            Accept server version
          </button>
        </div>

        <!-- Edit error (non-conflict) -->
        <div
          v-else-if="controller.editPhase === 'failed' && controller.editError"
          class="edit-error"
          role="alert"
        >
          <strong>{{ controller.editError.code }}</strong>
          <p>{{ controller.editError.message }}</p>
        </div>

        <div class="edit-actions">
          <button type="button" @click="controller.closeEditForm()">Cancel</button>
          <button
            type="button"
            class="primary"
            :disabled="controller.editPhase === 'saving'"
            @click="controller.saveEdit()"
          >
            {{ controller.editPhase === "saving" ? "Saving…" : "Save changes" }}
          </button>
        </div>
      </div>

      <!-- Read-only detail -->
      <template v-else>
        <div class="detail-field">
          <span class="field-label">Content</span>
          <p class="field-value content-value">{{ controller.detail.content }}</p>
        </div>

        <div v-if="controller.detail.summary" class="detail-field">
          <span class="field-label">Summary</span>
          <p class="field-value">{{ controller.detail.summary }}</p>
        </div>

        <div class="detail-meta">
          <div class="meta-item">
            <span class="meta-label">Source</span>
            <span class="meta-value">{{ controller.detail.source }}</span>
          </div>
          <div class="meta-item">
            <span class="meta-label">Importance</span>
            <span class="meta-value">{{ controller.detail.importance }}</span>
          </div>
          <div class="meta-item">
            <span class="meta-label">Confidence</span>
            <span class="meta-value">{{ controller.detail.confidence }}</span>
          </div>
          <div class="meta-item">
            <span class="meta-label">Created</span>
            <span class="meta-value">{{ formatTimestamp(controller.detail.createdAt) }}</span>
          </div>
          <div class="meta-item">
            <span class="meta-label">Updated</span>
            <span class="meta-value">{{ formatTimestamp(controller.detail.updatedAt) }}</span>
          </div>
          <div class="meta-item">
            <span class="meta-label">Revisions</span>
            <span class="meta-value">{{ controller.detail.revisionCount }}</span>
          </div>
        </div>

        <!-- Action buttons -->
        <div class="detail-actions">
          <button
            v-if="controller.detail.status === 'confirmed'"
            type="button"
            class="primary"
            @click="controller.openEditForm()"
          >
            Edit
          </button>

          <button
            type="button"
            :class="controller.detail.isSensitive ? 'warning' : ''"
            :disabled="controller.sensitivePhase === 'settingSensitive'"
            @click="controller.toggleSensitive()"
          >
            {{
              controller.sensitivePhase === "settingSensitive"
                ? "Updating…"
                : controller.detail.isSensitive
                  ? "Remove sensitive"
                  : "Mark sensitive"
            }}
          </button>

          <button type="button" @click="toggleRevisions">
            {{ showRevisions ? "Hide history" : "Show history" }}
          </button>

          <button
            type="button"
            class="danger"
            @click="controller.openDeleteConfirm()"
          >
            Delete permanently
          </button>
        </div>

        <!-- Sensitive error -->
        <div
          v-if="controller.sensitivePhase === 'failed' && controller.sensitiveError"
          class="inline-error"
          role="alert"
        >
          <strong>{{ controller.sensitiveError.code }}</strong>
          <p>{{ controller.sensitiveError.message }}</p>
        </div>

        <!-- Revision history -->
        <div v-if="showRevisions" class="revision-section">
          <h3>Revision History</h3>

          <div v-if="controller.revisionPhase === 'loadingRevisions'" class="loading-hint">
            Loading revisions…
          </div>

          <div
            v-else-if="controller.revisionPhase === 'failed'"
            class="inline-error"
            role="alert"
          >
            <strong>{{ controller.revisionError?.code }}</strong>
            <p>{{ controller.revisionError?.message }}</p>
            <button type="button" @click="controller.loadRevisions()">Retry</button>
          </div>

          <div
            v-else-if="controller.revisions.length === 0"
            class="empty-hint"
          >
            No revision history available.
          </div>

          <div v-else class="revision-list">
            <div
              v-for="rev in controller.revisions"
              :key="rev.revision"
              class="revision-item"
            >
              <div class="revision-header">
                <span class="revision-number">Rev {{ rev.revision }}</span>
                <span class="revision-change-type">{{ changeTypeLabel(rev.changeType) }}</span>
                <time class="revision-time" :datetime="rev.createdAt">
                  {{ formatTimestamp(rev.createdAt) }}
                </time>
              </div>
              <p class="revision-content">{{ rev.content }}</p>
              <div class="revision-meta">
                <span>Kind: {{ rev.kind }}</span>
                <span v-if="rev.summary">Summary: {{ rev.summary }}</span>
                <span>Sensitive: {{ rev.isSensitive ? "Yes" : "No" }}</span>
              </div>
            </div>
          </div>
        </div>

        <!-- Delete confirmation -->
        <div v-if="controller.deleteConfirmVisible" class="delete-confirmation">
          <h3>Confirm Permanent Deletion</h3>
          <p>
            This will permanently delete this memory's content, summary, and all revision history.
            Background cleanup will remove all derived search index entries.
          </p>
          <p>This does not affect Conversation, Persona, or other Memory records.</p>
          <p class="delete-warning">This action cannot be undone.</p>

          <dl class="delete-scope">
            <div>
              <dt>Memory ID</dt>
              <dd>{{ controller.detail.id }}</dd>
            </div>
            <div>
              <dt>Kind</dt>
              <dd>{{ controller.detail.kind }}</dd>
            </div>
            <div>
              <dt>Content preview</dt>
              <dd>{{ controller.detail.content.substring(0, 120) }}{{ controller.detail.content.length > 120 ? "…" : "" }}</dd>
            </div>
          </dl>

          <div
            v-if="controller.deletePhase === 'failed' && controller.deleteError"
            class="inline-error"
            role="alert"
          >
            <strong>{{ controller.deleteError.code }}</strong>
            <p>{{ controller.deleteError.message }}</p>
          </div>

          <div class="delete-actions">
            <button type="button" @click="controller.closeDeleteConfirm()">Cancel</button>
            <button
              type="button"
              class="danger"
              :disabled="controller.deletePhase === 'deleting'"
              @click="controller.confirmDelete()"
            >
              {{ controller.deletePhase === "deleting" ? "Deleting…" : "Confirm delete" }}
            </button>
          </div>
        </div>
      </template>
    </div>
  </section>
</template>

<style scoped>
.memory-detail-panel {
  display: grid;
  gap: 0.75rem;
}

.empty-state {
  display: grid;
  gap: 0.5rem;
  border: 1px dashed #475569;
  border-radius: 0.7rem;
  color: #cbd5e1;
  padding: 1rem;
}

.error {
  border-color: #dc2626;
  color: #fecaca;
}

.detail-content {
  display: grid;
  gap: 0.75rem;
  border: 1px solid #334155;
  border-radius: 0.75rem;
  background: #172033;
  padding: 1rem;
}

.detail-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.detail-badges {
  display: flex;
  gap: 0.4rem;
  align-items: center;
  flex-wrap: wrap;
}

.kind-badge {
  font-size: 0.75rem;
  font-weight: 600;
  padding: 0.15rem 0.45rem;
  border-radius: 0.3rem;
  background: #1e293b;
  color: #94a3b8;
  border: 1px solid #475569;
}

.status-badge {
  font-size: 0.7rem;
  font-weight: 600;
  padding: 0.1rem 0.35rem;
  border-radius: 0.25rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.status-confirmed {
  background: #064e3b;
  color: #6ee7b7;
}

.status-candidate {
  background: #78350f;
  color: #fcd34d;
}

.sensitive-badge {
  font-size: 0.7rem;
  font-weight: 600;
  padding: 0.1rem 0.35rem;
  border-radius: 0.25rem;
  background: #7f1d1d;
  color: #fca5a5;
}

.revision-info {
  font-size: 0.8rem;
  color: #64748b;
}

.detail-field {
  display: grid;
  gap: 0.3rem;
}

.field-label {
  font-weight: 700;
  font-size: 0.85rem;
  color: #94a3b8;
}

.field-value {
  margin: 0;
  color: #e2e8f0;
  font-size: 0.9rem;
  white-space: pre-wrap;
  word-break: break-word;
}

.content-value {
  border: 1px solid #334155;
  border-radius: 0.45rem;
  padding: 0.6rem;
  background: #0f172a;
}

.detail-meta {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.5rem;
}

.meta-item {
  display: grid;
  gap: 0.15rem;
}

.meta-label {
  font-size: 0.75rem;
  color: #64748b;
}

.meta-value {
  font-size: 0.85rem;
  color: #cbd5e1;
}

.detail-actions {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.primary {
  border-color: #0284c7;
  background: #0369a1;
}

.danger {
  border-color: #dc2626;
  background: #991b1b;
}

.warning {
  border-color: #f59e0b;
  background: #92400e;
}

.inline-error {
  border: 1px solid #dc2626;
  border-radius: 0.5rem;
  padding: 0.6rem;
  color: #fecaca;
  display: grid;
  gap: 0.3rem;
}

.inline-error strong {
  font-size: 0.85rem;
}

.inline-error p {
  margin: 0;
  font-size: 0.85rem;
}

/* Edit form */
.edit-form {
  display: grid;
  gap: 0.75rem;
}

.edit-form h3 {
  margin: 0;
  font-size: 1rem;
}

.edit-form label {
  display: grid;
  gap: 0.3rem;
}

.edit-form select,
.edit-form input,
.edit-form textarea {
  border: 1px solid #475569;
  border-radius: 0.45rem;
  background: #0f172a;
  color: #f8fafc;
  padding: 0.5rem 0.65rem;
  font: inherit;
}

.edit-form textarea {
  resize: vertical;
  min-height: 5rem;
}

.edit-actions {
  display: flex;
  gap: 0.5rem;
  justify-content: flex-end;
}

.edit-error {
  border: 1px solid #dc2626;
  border-radius: 0.5rem;
  padding: 0.6rem;
  color: #fecaca;
  display: grid;
  gap: 0.3rem;
}

.conflict-banner {
  border: 1px solid #f59e0b;
  border-radius: 0.5rem;
  padding: 0.75rem;
  background: #451a03;
  display: grid;
  gap: 0.5rem;
}

.conflict-banner strong {
  color: #fbbf24;
}

.conflict-banner p {
  margin: 0;
  font-size: 0.85rem;
  color: #fde68a;
}

.conflict-latest {
  border: 1px solid #78350f;
  border-radius: 0.4rem;
  padding: 0.5rem;
  background: #1c1917;
}

.conflict-content {
  white-space: pre-wrap;
  word-break: break-word;
  color: #e2e8f0;
}

/* Revision section */
.revision-section {
  display: grid;
  gap: 0.5rem;
  border: 1px solid #334155;
  border-radius: 0.5rem;
  padding: 0.75rem;
  background: #0f172a;
}

.revision-section h3 {
  margin: 0;
  font-size: 0.95rem;
}

.loading-hint,
.empty-hint {
  color: #64748b;
  font-size: 0.85rem;
}

.revision-list {
  display: grid;
  gap: 0.5rem;
}

.revision-item {
  border: 1px solid #1e293b;
  border-radius: 0.4rem;
  padding: 0.5rem;
  display: grid;
  gap: 0.3rem;
}

.revision-header {
  display: flex;
  gap: 0.5rem;
  align-items: center;
  flex-wrap: wrap;
}

.revision-number {
  font-weight: 700;
  font-size: 0.8rem;
  color: #38bdf8;
}

.revision-change-type {
  font-size: 0.75rem;
  color: #a78bfa;
}

.revision-time {
  font-size: 0.75rem;
  color: #64748b;
  margin-left: auto;
}

.revision-content {
  margin: 0;
  font-size: 0.8rem;
  color: #cbd5e1;
  white-space: pre-wrap;
  word-break: break-word;
}

.revision-meta {
  display: flex;
  gap: 0.75rem;
  flex-wrap: wrap;
  font-size: 0.75rem;
  color: #64748b;
}

/* Delete confirmation */
.delete-confirmation {
  border: 1px solid #dc2626;
  border-radius: 0.5rem;
  padding: 0.75rem;
  background: #1c0a0a;
  display: grid;
  gap: 0.5rem;
}

.delete-confirmation h3 {
  margin: 0;
  color: #fca5a5;
  font-size: 1rem;
}

.delete-confirmation p {
  margin: 0;
  font-size: 0.85rem;
  color: #fecaca;
}

.delete-warning {
  font-weight: 700;
  color: #f87171 !important;
}

.delete-scope {
  display: grid;
  gap: 0.4rem;
  margin: 0;
  border: 1px solid #7f1d1d;
  border-radius: 0.4rem;
  padding: 0.5rem;
  background: #0f172a;
}

.delete-scope div {
  display: grid;
  gap: 0.15rem;
}

.delete-scope dt {
  font-size: 0.75rem;
  color: #64748b;
}

.delete-scope dd {
  margin: 0;
  font-size: 0.85rem;
  color: #e2e8f0;
  overflow-wrap: anywhere;
}

.delete-actions {
  display: flex;
  gap: 0.5rem;
  justify-content: flex-end;
}

@media (max-width: 860px) {
  .detail-meta {
    grid-template-columns: 1fr;
  }
}
</style>
