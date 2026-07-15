<script setup lang="ts">
import { computed, ref, watch, onMounted, onUnmounted, nextTick } from "vue";
import type {
  PreparedCandidateConfirmationPreview,
  CandidateConfirmationError,
} from "../../memory/candidateConfirmationTypes.ts";
import type { CandidateConfirmationPhase } from "../../stores/candidateConfirmation.ts";

// ── Props ─────────────────────────────────────────────────────────────

interface Props {
  open: boolean;
  prepared: PreparedCandidateConfirmationPreview | null;
  phase: CandidateConfirmationPhase;
  error: CandidateConfirmationError | null;
  cancelOutcomeUnknown: boolean;
  isReloadingAuthoritativeState: boolean;
  authoritativeReloadFailed: boolean;
}

const props = defineProps<Props>();

// ── Events ────────────────────────────────────────────────────────────

const emit = defineEmits<{
  confirm: [];
  cancel: [];
  close: [];
  retryPrepare: [];
  retryConfirm: [];
  reloadAuthoritativeState: [];
}>();

// ── Refs ──────────────────────────────────────────────────────────────

const dialogRef = ref<HTMLDialogElement | null>(null);
const closeButtonRef = ref<HTMLButtonElement | null>(null);
const previousFocus = ref<HTMLElement | null>(null);

// ── Computed ──────────────────────────────────────────────────────────

const isSensitive = computed(
  () => props.prepared?.confirmationRequirement === "explicitSensitiveApproval",
);

const isLoading = computed(
  () =>
    props.phase === "preparing" ||
    props.phase === "confirming" ||
    props.phase === "cancelling",
);

const isCloseLocked = computed(
  () => props.phase === "confirming" || props.phase === "cancelling",
);

const isExpired = computed(() => {
  if (!props.prepared?.expiresAt) return false;
  const timestamp = Date.parse(props.prepared.expiresAt);
  return !Number.isFinite(timestamp) || Date.now() > timestamp;
});

const errorAction = computed(() => props.error?.action ?? null);

const canConfirm = computed(
  () =>
    props.phase === "prepared" &&
    props.prepared !== null &&
    !isExpired.value &&
    !isLoading.value &&
    errorAction.value !== "none",
);

const canCancel = computed(
  () =>
    props.phase === "prepared" &&
    !isLoading.value,
);

const kindLabel = computed(() => {
  if (!props.prepared) return "";
  const map: Record<string, string> = {
    experience: "体验",
    preference: "偏好",
    fact: "事实",
    relationship: "关系",
    goal: "目标",
    skill: "技能",
    other: "其他",
  };
  return map[props.prepared.kind] ?? props.prepared.kind;
});

const requirementLabel = computed(() => {
  if (!props.prepared) return "";
  return props.prepared.confirmationRequirement === "explicitSensitiveApproval"
    ? "需要明确敏感授权"
    : "标准确认";
});

const sourceLabel = computed(() => {
  if (!props.prepared) return "";
  const map: Record<string, string> = {
    conversation: "对话",
    manual: "手动",
    system: "系统",
    import: "导入",
  };
  return map[props.prepared.source] ?? props.prepared.source;
});

const errorMessage = computed(() => {
  if (!props.error) return "";
  // Use safe fixed message, never raw error
  return props.error.message;
});

// ── Dialog Management ─────────────────────────────────────────────────

watch(
  () => props.open,
  async (isOpen) => {
    if (isOpen) {
      previousFocus.value = document.activeElement as HTMLElement;
      await nextTick();
      if (!props.open || !dialogRef.value) return;
      if (!dialogRef.value.open) dialogRef.value.showModal();
      closeButtonRef.value?.focus();
    } else {
      if (dialogRef.value?.open) dialogRef.value.close();
      if (previousFocus.value?.isConnected) previousFocus.value.focus();
    }
  },
  { immediate: true },
);

// ── Keyboard Handling ─────────────────────────────────────────────────

function handleKeydown(event: KeyboardEvent) {
  if (props.open && event.key === "Escape") {
    event.preventDefault();
    handleEscape();
  }
}

function handleEscape() {
  requestClose();
}

// ── Actions ───────────────────────────────────────────────────────────

function handleConfirm() {
  if (!canConfirm.value) return;
  emit("confirm");
}

function handleCancel() {
  if (!canCancel.value) return;
  emit("cancel");
}

function handleClose() {
  requestClose();
}

function requestClose() {
  if (isCloseLocked.value) return;
  if (props.phase === "prepared") {
    emit("cancel");
  } else {
    emit("close");
  }
}

function handleRetryPrepare() {
  emit("retryPrepare");
}

function handleRetryConfirm() {
  if (canConfirm.value) emit("retryConfirm");
}

function handleReloadAuthoritativeState() {
  if (!props.cancelOutcomeUnknown || props.isReloadingAuthoritativeState) return;
  emit("reloadAuthoritativeState");
}

// ── Lifecycle ─────────────────────────────────────────────────────────

onMounted(() => {
  document.addEventListener("keydown", handleKeydown);
});

onUnmounted(() => {
  document.removeEventListener("keydown", handleKeydown);
});
</script>

<template>
  <dialog
    ref="dialogRef"
    class="confirmation-dialog"
    role="dialog"
    aria-modal="true"
    aria-labelledby="confirmation-title"
    :aria-busy="isLoading"
    @cancel.prevent="handleEscape"
  >
    <!-- Backdrop -->
    <div class="dialog-backdrop" @click="handleClose"></div>

    <!-- Dialog Content -->
    <div class="dialog-content">
      <!-- Header -->
      <header class="dialog-header">
        <h2 id="confirmation-title">
          {{ isSensitive ? "确认保存敏感记忆" : "确认保存记忆" }}
        </h2>
        <button
          ref="closeButtonRef"
          class="close-btn"
          type="button"
          :disabled="isCloseLocked"
          aria-label="关闭"
          @click="handleClose"
        >
          &times;
        </button>
      </header>

      <!-- Loading State -->
      <div v-if="phase === 'preparing'" class="dialog-loading" role="status">
        <div class="spinner"></div>
        <p>正在准备确认...</p>
      </div>

      <!-- Preview Content -->
      <div v-else class="dialog-body">
        <template v-if="prepared">
        <!-- Sensitive Warning -->
        <div
          v-if="isSensitive"
          class="sensitive-warning-banner"
          role="alert"
        >
          <strong>敏感记忆</strong>
          <p>此记忆包含敏感信息，确认后将保存到长期记忆中。</p>
        </div>

        <!-- Preview Fields -->
        <div class="preview-fields">
          <div class="preview-field">
            <span class="field-label">类型</span>
            <span class="field-value kind-badge">{{ kindLabel }}</span>
          </div>

          <div class="preview-field">
            <span class="field-label">来源</span>
            <span class="field-value">{{ sourceLabel }}</span>
          </div>

          <div class="preview-field">
            <span class="field-label">确认要求</span>
            <span
              class="field-value"
              :class="{ 'sensitive-requirement': isSensitive }"
            >
              {{ requirementLabel }}
            </span>
          </div>

          <div class="preview-field full-width">
            <span class="field-label">内容</span>
            <div class="field-content">
              {{ prepared.content ?? "无正文" }}
            </div>
          </div>

          <div class="preview-field full-width">
            <span class="field-label">摘要</span>
            <div class="field-content summary">
              {{ prepared.summary ?? "暂无摘要" }}
            </div>
          </div>

          <!-- Expired Warning -->
          <div v-if="isExpired" class="expired-warning" role="alert">
            本次确认授权已过期，请重新准备。
          </div>
        </div>

        </template>

        <div v-if="phase === 'confirming'" class="dialog-loading" role="status">
          <div class="spinner"></div>
          <p>正在确认保存...</p>
        </div>
        <div v-else-if="phase === 'cancelling'" class="dialog-loading" role="status">
          <div class="spinner"></div>
          <p>正在取消确认...</p>
        </div>

        <!-- Cancel outcome unknown: local authorization has been cleared and only a read refresh is allowed. -->
        <div v-if="cancelOutcomeUnknown" class="error-banner uncertain-cancel-banner" role="alert">
          <p class="error-message">
            未能确认后端是否已取消，本地授权信息已清除。请重新加载候选状态以确认当前结果。
          </p>
          <p v-if="authoritativeReloadFailed" class="error-message">
            重新加载失败，请稍后再试。
          </p>
          <div class="error-actions">
            <button
              class="btn btn-secondary reload-authoritative-state"
              type="button"
              :disabled="isReloadingAuthoritativeState"
              @click="handleReloadAuthoritativeState"
            >
              {{ isReloadingAuthoritativeState ? "正在重新加载..." : "重新加载候选状态" }}
            </button>
            <button class="btn btn-secondary uncertain-cancel-close" type="button" @click="handleClose">
              关闭
            </button>
          </div>
        </div>

        <!-- Error Display, including failed states whose preview was cleared by the Store -->
        <div v-else-if="error" class="error-banner" role="alert">
          <p class="error-message">{{ errorMessage }}</p>

          <!-- Reprepare action -->
          <div v-if="errorAction === 'reprepare'" class="error-actions">
            <button
              class="btn btn-secondary"
              type="button"
              @click="handleRetryPrepare"
            >
              重新准备
            </button>
          </div>

          <!-- Retry same token -->
          <div v-else-if="errorAction === 'retrySameToken'" class="error-actions">
            <button
              class="btn btn-secondary"
              type="button"
              :disabled="isLoading"
              @click="handleRetryConfirm"
            >
              重试
            </button>
          </div>

          <!-- Retry prepare later -->
          <div v-else-if="errorAction === 'retryPrepareLater'" class="error-actions">
            <button
              class="btn btn-secondary"
              type="button"
              @click="handleRetryPrepare"
            >
              稍后重试
            </button>
          </div>

          <!-- None (fatal) -->
          <div v-else-if="errorAction === 'none'" class="error-actions">
            <button
              class="btn btn-secondary"
              type="button"
              @click="handleClose"
            >
              关闭
            </button>
          </div>
        </div>
        <div v-else-if="phase === 'failed'" class="error-banner" role="alert">
          <p class="error-message">确认操作未能完成，请关闭后重新加载候选状态。</p>
          <div class="error-actions">
            <button class="btn btn-secondary" type="button" @click="handleClose">关闭</button>
          </div>
        </div>
      </div>

      <!-- Footer Actions -->
      <footer
        v-if="prepared && phase === 'prepared'"
        class="dialog-footer"
      >
        <button
          class="btn btn-cancel"
          type="button"
          :disabled="!canCancel"
          @click="handleCancel"
        >
          取消
        </button>

        <button
          v-if="isSensitive"
          class="btn btn-confirm-sensitive"
          type="button"
          :disabled="!canConfirm"
          @click="handleConfirm"
        >
          确认保存敏感记忆
        </button>
        <button
          v-else
          class="btn btn-confirm"
          type="button"
          :disabled="!canConfirm"
          @click="handleConfirm"
        >
          确认保存
        </button>
      </footer>
    </div>
  </dialog>
</template>

<style scoped>
/* ── Dialog Base ──────────────────────────────────────────────────── */

.confirmation-dialog {
  border: none;
  border-radius: 0.75rem;
  background: transparent;
  padding: 0;
  max-width: min(480px, 90vw);
  width: 100%;
  overflow: visible;
}

.confirmation-dialog::backdrop {
  background: rgba(0, 0, 0, 0.6);
  backdrop-filter: blur(4px);
}

.dialog-backdrop {
  position: fixed;
  inset: 0;
  z-index: -1;
}

/* ── Dialog Content ───────────────────────────────────────────────── */

.dialog-content {
  background: rgba(15, 23, 42, 0.95);
  backdrop-filter: blur(16px);
  border: 1px solid rgba(51, 65, 85, 0.8);
  border-radius: 0.75rem;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
  display: flex;
  flex-direction: column;
  max-height: 85vh;
}

/* ── Header ───────────────────────────────────────────────────────── */

.dialog-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1.25rem 1.5rem;
  border-bottom: 1px solid #334155;
}

.dialog-header h2 {
  margin: 0;
  font-size: 1.15rem;
  color: #f8fafc;
  font-weight: 600;
}

.close-btn {
  background: none;
  border: none;
  color: #94a3b8;
  font-size: 1.75rem;
  cursor: pointer;
  line-height: 1;
  padding: 0.25rem;
  transition: color 0.2s ease;
}

.close-btn:hover:not(:disabled) {
  color: #f8fafc;
}

.close-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

/* ── Loading ──────────────────────────────────────────────────────── */

.dialog-loading {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 3rem 1.5rem;
  color: #94a3b8;
}

.spinner {
  width: 40px;
  height: 40px;
  border: 3px solid rgba(148, 163, 184, 0.2);
  border-top-color: #38bdf8;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin-bottom: 1rem;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

/* ── Body ─────────────────────────────────────────────────────────── */

.dialog-body {
  padding: 1.5rem;
  overflow-y: auto;
  flex: 1;
}

/* ── Sensitive Warning ────────────────────────────────────────────── */

.sensitive-warning-banner {
  background: rgba(249, 115, 22, 0.1);
  border: 1px solid rgba(249, 115, 22, 0.3);
  border-radius: 0.5rem;
  padding: 0.75rem 1rem;
  margin-bottom: 1rem;
  color: #fdba74;
  font-size: 0.85rem;
  line-height: 1.5;
}

.sensitive-warning-banner strong {
  display: block;
  margin-bottom: 0.25rem;
  color: #f97316;
}

.sensitive-warning-banner p {
  margin: 0;
}

/* ── Preview Fields ───────────────────────────────────────────────── */

.preview-fields {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1rem;
}

.preview-field {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.preview-field.full-width {
  grid-column: 1 / -1;
}

.field-label {
  font-size: 0.75rem;
  color: #94a3b8;
  font-weight: 500;
}

.field-value {
  font-size: 0.875rem;
  color: #f1f5f9;
}

.field-content {
  font-size: 0.875rem;
  color: #f1f5f9;
  background: rgba(0, 0, 0, 0.2);
  border: 1px solid #334155;
  border-radius: 0.375rem;
  padding: 0.75rem;
  white-space: pre-wrap;
  word-break: break-word;
  max-height: 200px;
  overflow-y: auto;
}

.field-content.summary {
  color: #cbd5e1;
  font-size: 0.8rem;
}

.kind-badge {
  background: #334155;
  padding: 0.15rem 0.4rem;
  border-radius: 0.25rem;
  font-size: 0.8rem;
  display: inline-block;
  width: fit-content;
}

.sensitive-requirement {
  color: #f97316;
  font-weight: 500;
}

/* ── Expired Warning ──────────────────────────────────────────────── */

.expired-warning {
  grid-column: 1 / -1;
  background: rgba(239, 68, 68, 0.1);
  border: 1px solid rgba(239, 68, 68, 0.3);
  border-radius: 0.5rem;
  padding: 0.75rem;
  color: #fca5a5;
  font-size: 0.85rem;
  text-align: center;
}

/* ── Error Banner ─────────────────────────────────────────────────── */

.error-banner {
  margin-top: 1rem;
  background: rgba(239, 68, 68, 0.1);
  border: 1px solid rgba(239, 68, 68, 0.3);
  border-radius: 0.5rem;
  padding: 0.75rem 1rem;
  color: #fca5a5;
}

.error-message {
  margin: 0 0 0.75rem;
  font-size: 0.85rem;
  line-height: 1.5;
}

.error-actions {
  display: flex;
  gap: 0.5rem;
}

/* ── Footer ───────────────────────────────────────────────────────── */

.dialog-footer {
  display: flex;
  justify-content: flex-end;
  gap: 0.75rem;
  padding: 1rem 1.5rem;
  border-top: 1px solid #334155;
}

/* ── Buttons ──────────────────────────────────────────────────────── */

.btn {
  cursor: pointer;
  border-radius: 0.375rem;
  font-size: 0.85rem;
  font-weight: 500;
  padding: 0.5rem 1rem;
  transition: all 0.2s ease;
  border: 1px solid transparent;
}

.btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
  transform: none !important;
  box-shadow: none !important;
}

.btn-cancel {
  background: #334155;
  border-color: #475569;
  color: #f1f5f9;
}

.btn-cancel:hover:not(:disabled) {
  background: #475569;
  border-color: #64748b;
}

.btn-confirm {
  background: linear-gradient(135deg, #059669 0%, #047857 100%);
  color: #ffffff;
  box-shadow: 0 2px 4px rgba(5, 150, 105, 0.25);
}

.btn-confirm:hover:not(:disabled) {
  background: linear-gradient(135deg, #10b981 0%, #059669 100%);
  transform: translateY(-1px);
}

.btn-confirm-sensitive {
  background: linear-gradient(135deg, #d97706 0%, #b45309 100%);
  color: #ffffff;
  box-shadow: 0 2px 4px rgba(217, 119, 6, 0.25);
}

.btn-confirm-sensitive:hover:not(:disabled) {
  background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
  transform: translateY(-1px);
}

.btn-secondary {
  background: #334155;
  border-color: #475569;
  color: #f1f5f9;
}

.btn-secondary:hover:not(:disabled) {
  background: #475569;
  border-color: #64748b;
}

/* ── Mobile ───────────────────────────────────────────────────────── */

@media (max-width: 640px) {
  .confirmation-dialog {
    max-width: 100vw;
    max-height: 100vh;
    width: 100vw;
    height: 100vh;
    border-radius: 0;
  }

  .dialog-content {
    border-radius: 0;
    max-height: 100vh;
    height: 100vh;
  }

  .preview-fields {
    grid-template-columns: 1fr;
  }

  .dialog-footer {
    flex-direction: column;
  }

  .dialog-footer .btn {
    width: 100%;
    text-align: center;
  }
}
</style>
