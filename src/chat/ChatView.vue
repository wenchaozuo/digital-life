<script setup lang="ts">
import { invoke } from "@tauri-apps/api/core";
import { computed, onMounted, onUnmounted, ref, reactive } from "vue";
import { bodyStateMachine, type BodyState } from "../body";
import {
  ConversationError,
  conversationService,
  type ConversationMessage,
} from "../conversation";
import ChatInput from "./ChatInput.vue";
import MessageBubble from "./MessageBubble.vue";
import { MemoryReviewController } from "./memoryReviewController";
import { memoryService, memoryExtractor } from "../memory";
import { lifeIdentityManager } from "../life";
import { createClosePanelHandler } from "./memoryReviewAdapter";

const bodyState = ref<BodyState>(bodyStateMachine.getState());
const messages = ref<readonly ConversationMessage[]>([]);
const error = ref<{ code: string; message: string }>();
const isSending = ref(false);
const clearSignal = ref(0);
const memoryNotice = ref<string>();
const modelSetupErrorCodes = new Set([
  "NO_ACTIVE_PROFILE",
  "PROFILE_NOT_FOUND",
  "PROFILE_PURPOSE_MISMATCH",
  "CREDENTIAL_NOT_FOUND",
  "UNSUPPORTED_PROVIDER",
  "PROVIDER_INITIALIZATION_FAILED",
]);
const showModelSettingsAction = computed(() =>
  error.value ? modelSetupErrorCodes.has(error.value.code) : false,
);
const visibleMessages = computed(() => messages.value);

const showMemoryPanel = ref(false);
const showUnconfirmedHint = ref(false);
const controller = reactive(new MemoryReviewController(memoryService, memoryExtractor));

let unsubscribeMessages: (() => void) | undefined;
let unsubscribeBodyState: (() => void) | undefined;

function refreshMessages(): void {
  messages.value = conversationService.getSession().getMessages();
}

function memoryNoticeFor(codes: readonly string[], rebuildRecommended: boolean): string | undefined {
  if (rebuildRecommended) return "Vector memory may need rebuilding.";
  if (codes.includes("KEYWORD_UNAVAILABLE") || codes.includes("BOTH_RETRIEVAL_UNAVAILABLE")) {
    return "Memory retrieval was unavailable; this reply used persona and session context.";
  }
  if (codes.length > 0) return "Vector memory was unavailable; keyword memory was used when available.";
  return undefined;
}

async function send(content: string): Promise<void> {
  if (isSending.value) {
    return;
  }

  isSending.value = true;
  error.value = undefined;

  try {
    const response = await conversationService.send({
      userInput: content,
    });
    clearSignal.value += 1;
    memoryNotice.value = memoryNoticeFor(response.memory.degradationCodes, response.memory.rebuildRecommended);
  } catch (caught) {
    error.value = caught instanceof ConversationError
      ? { code: caught.code, message: caught.message }
      : {
          code: "CONVERSATION_MODEL_FAILED",
          message: "The model request could not be completed.",
        };
  } finally {
    refreshMessages();
    isSending.value = false;
  }
}

async function openModelSettings(): Promise<void> {
  await invoke("open_settings_window");
}

async function toggleMemoryPanel() {
  if (showMemoryPanel.value) {
    handleClosePanel();
  } else {
    const life = await lifeIdentityManager.getCurrent();
    if (life) {
      controller.setLifeId(life.id);
    }
    const sessionMessages = conversationService.getSession().getMessages();
    await controller.extract(sessionMessages);
    showMemoryPanel.value = true;
  }
}

const handleClosePanel = createClosePanelHandler(controller, {
  showMemoryPanel,
  showUnconfirmedHint,
});

onMounted(() => {
  refreshMessages();
  unsubscribeMessages = conversationService.getSession().subscribe(refreshMessages);
  unsubscribeBodyState = bodyStateMachine.subscribe(({ current }) => {
    bodyState.value = current;
  });
});

onUnmounted(() => {
  unsubscribeMessages?.();
  unsubscribeBodyState?.();
});
</script>

<template>
  <main class="chat-page">
    <header class="chat-header">
      <div>
        <p class="eyebrow">Digital Life</p>
        <h1>Chat</h1>
      </div>
      <span>Body state: {{ bodyState }}</span>
    </header>

    <!-- Runtime Persistence Notification Warning Banner -->
    <div v-if="showUnconfirmedHint" class="unconfirmed-warning-banner">
      <span>⚠️ 部分候选已保存到数据库，但当前面板暂不支持重新加载历史候选。</span>
      <button class="close-banner-btn" type="button" @click="showUnconfirmedHint = false">&times;</button>
    </div>

    <div class="chat-actions">
      <button class="memory-check-btn" type="button" @click="toggleMemoryPanel">
        检查可记忆内容
      </button>
    </div>

    <section class="message-list" aria-label="Conversation messages">
      <p v-if="visibleMessages.length === 0" class="empty-state">No messages in this runtime session.</p>
      <MessageBubble
        v-for="(message, index) in visibleMessages"
        v-else
        :key="`${message.timestamp}-${index}`"
        :message="message"
      />
    </section>

    <section v-if="error" class="chat-error" aria-live="polite">
      <strong>{{ error.code }}</strong>
      <span>{{ error.message }}</span>
      <button v-if="showModelSettingsAction" type="button" @click="openModelSettings">
        Open model settings
      </button>
    </section>
    <p v-if="memoryNotice" class="memory-notice" aria-live="polite">{{ memoryNotice }}</p>
    <ChatInput :disabled="isSending" :clear-signal="clearSignal" @send="send" />
  </main>

  <!-- Backdrop Overlay -->
  <div v-if="showMemoryPanel" class="memory-panel-backdrop" @click="handleClosePanel"></div>

  <!-- Memory Review Panel Drawer -->
  <aside class="memory-panel" :class="{ 'is-open': showMemoryPanel }">
    <div class="memory-panel-header">
      <h2>候选记忆检查</h2>
      <button class="close-btn" type="button" @click="handleClosePanel">&times;</button>
    </div>

    <div class="memory-panel-content">
      <div v-if="controller.panelState === 'extracting'" class="loading-state">
        <div class="spinner"></div>
        <p>正在分析对话，提取可记忆内容...</p>
      </div>

      <div v-else-if="controller.panelState === 'empty'" class="empty-state-container">
        <div class="empty-icon">📂</div>
        <h3>暂无可记忆内容</h3>
        <p>当前对话 session 中未提取到新的 Preference、Fact、Goal 等候选记忆。</p>
        <button class="refresh-btn" type="button" @click="toggleMemoryPanel">重新检查</button>
      </div>

      <div v-else-if="controller.panelState === 'failed' && controller.error" class="error-state">
        <p class="error-title">提取失败 (阶段: {{ controller.error.stage }})</p>
        <p class="error-code">错误代码: {{ controller.error.code }}</p>
        <p class="error-message">{{ controller.error.message }}</p>
        <button class="retry-btn" type="button" @click="toggleMemoryPanel">重试</button>
      </div>

      <div v-else-if="controller.panelState === 'reviewing'" class="candidate-list-container">
        <!-- Persistent Drawer Info Explanation Notice -->
        <div class="panel-notice-info">
          ℹ️ 已入库候选仍在数据库中，但当前页面暂不支持重新加载历史候选。
        </div>
        <div class="list-summary">
          待审查候选: <strong>{{ controller.candidates.length }}</strong> 条
        </div>

        <div v-for="(candidate, index) in controller.candidates" :key="candidate.id" class="candidate-card" :class="`state-${candidate.state}`">
          <!-- Card Header: Type Badge & State Status -->
          <div class="card-header">
            <select
              v-model="candidate.kind"
              :disabled="candidate.state === 'confirmed' || candidate.state === 'creatingCandidate' || candidate.state === 'confirming' || candidate.state === 'deleting' || candidate.state === 'updating'"
              class="kind-select"
            >
              <option value="experience">Experience</option>
              <option value="preference">Preference</option>
              <option value="fact">Fact</option>
              <option value="relationship">Relationship</option>
              <option value="goal">Goal</option>
              <option value="skill">Skill</option>
              <option value="other">Other</option>
            </select>

            <span class="badge source-badge">{{ candidate.sourceType }}</span>
            <span v-if="candidate.isSensitive" class="badge sensitive-badge">⚠️ 敏感</span>
          </div>

          <!-- Card Content Inputs -->
          <div class="card-body">
            <label class="input-label">
              <span>记忆内容 (Content)</span>
              <textarea
                v-model="candidate.content"
                :disabled="candidate.state === 'confirmed' || candidate.state === 'creatingCandidate' || candidate.state === 'confirming' || candidate.state === 'deleting' || candidate.state === 'updating'"
                rows="2"
                class="edit-textarea"
                placeholder="记忆的具体内容"
              ></textarea>
            </label>

            <label class="input-label">
              <span>总结说明 (Summary)</span>
              <textarea
                v-model="candidate.summary"
                :disabled="candidate.state === 'confirmed' || candidate.state === 'creatingCandidate' || candidate.state === 'confirming' || candidate.state === 'deleting' || candidate.state === 'updating'"
                rows="1.5"
                class="edit-textarea"
                placeholder="简短总结"
              ></textarea>
            </label>

            <!-- Read-only Metrics -->
            <div class="metrics-row">
              <span title="Importance">⭐ 重要度: {{ candidate.importance.toFixed(2) }}</span>
              <span title="Confidence">🎯 置信度: {{ candidate.confidence.toFixed(2) }}</span>
            </div>

            <!-- Sensitive Consent Checkbox -->
            <div v-if="candidate.isSensitive && candidate.state !== 'confirmed'" class="sensitive-consent-container">
              <div class="sensitive-warning">
                此条记忆包含敏感信息。
              </div>
              <label class="checkbox-label">
                <input
                  type="checkbox"
                  v-model="candidate.sensitiveConsentChecked"
                  :disabled="candidate.state === 'creatingCandidate' || candidate.state === 'confirming' || candidate.state === 'deleting' || candidate.state === 'updating'"
                />
                <span>我确认并明确同意存入长期记忆</span>
              </label>
            </div>

            <!-- Database Candidate Record details if created -->
            <div v-if="candidate.dbRecord" class="db-details">
              <div><strong>ID:</strong> <code class="db-id">{{ candidate.dbRecord.id }}</code></div>
              <div><strong>状态:</strong> <span class="db-status-badge" :class="candidate.dbRecord.status">{{ candidate.dbRecord.status }}</span></div>
              <div v-if="candidate.dbRecord.confirmedAt"><strong>确认时间:</strong> {{ new Date(candidate.dbRecord.confirmedAt).toLocaleString() }}</div>
            </div>

            <!-- Error banner -->
            <div v-if="candidate.error" class="card-error-banner">
              <div class="error-header">操作失败 (阶段: {{ candidate.error.stage }})</div>
              <div><strong>错误代码:</strong> <code>{{ candidate.error.code }}</code></div>
              <div>{{ candidate.error.message }}</div>
            </div>
          </div>

          <!-- Card Actions -->
          <div class="card-actions">
            <!-- Stage 1: Join Candidate Memory -->
            <button
              v-if="candidate.state === 'draft'"
              class="btn btn-primary"
              type="button"
              @click="controller.createCandidate(index)"
            >
              加入候选记忆
            </button>

            <!-- Save Changes -->
            <button
              v-if="candidate.state === 'candidateCreated' && controller.isModified(index)"
              class="btn btn-save"
              type="button"
              @click="controller.updateCandidate(index)"
            >
              保存修改
            </button>

            <!-- Stage 2: Confirm Long-term Memory -->
            <button
              v-if="candidate.state === 'candidateCreated'"
              class="btn btn-confirm"
              type="button"
              :disabled="candidate.isSensitive && !candidate.sensitiveConsentChecked"
              @click="controller.confirmCandidate(index)"
            >
              确认长期记住
            </button>

            <!-- Discard draft OR Delete candidate -->
            <button
              v-if="candidate.state !== 'confirmed'"
              class="btn btn-danger"
              type="button"
              :disabled="candidate.state === 'deleting' || candidate.state === 'creatingCandidate' || candidate.state === 'confirming' || candidate.state === 'updating'"
              @click="controller.deleteCandidate(index)"
            >
              {{ candidate.dbRecord ? '从数据库删除' : '丢弃' }}
            </button>

            <!-- Confirmed success state -->
            <span v-if="candidate.state === 'confirmed'" class="confirmed-success-badge">
              ✓ 已长期记住
            </span>
          </div>
        </div>
      </div>
    </div>
  </aside>
</template>

<style>
:root {
  color: #e2e8f0;
  background: #0f172a;
  font-family: Inter, ui-sans-serif, system-ui, sans-serif;
}

html,
body,
#app {
  min-width: 100%;
  min-height: 100%;
  margin: 0;
  background: #0f172a;
}

button,
input {
  font: inherit;
}

.chat-page {
  display: grid;
  grid-template-rows: auto auto minmax(0, 1fr) auto auto;
  gap: 0.85rem;
  min-height: 100vh;
  box-sizing: border-box;
  padding: 1rem;
}

.chat-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
}

.chat-header h1,
.chat-header p {
  margin: 0;
}

.eyebrow {
  color: #7dd3fc;
  font-size: 0.8rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.system-toggle {
  cursor: pointer;
}

.chat-actions {
  display: flex;
  gap: 0.75rem;
  justify-self: start;
}

.system-toggle,
.memory-check-btn {
  cursor: pointer;
  border: 1px solid #475569;
  border-radius: 0.45rem;
  background: #1e293b;
  color: #e2e8f0;
  padding: 0.4rem 0.6rem;
  transition: all 0.2s ease;
}

.system-toggle:hover {
  background: #334155;
  border-color: #64748b;
}

.memory-check-btn {
  background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%);
  border-color: #0284c7;
  font-weight: 500;
  box-shadow: 0 2px 4px rgba(2, 132, 199, 0.2);
}

.memory-check-btn:hover {
  background: linear-gradient(135deg, #0ea5e9 0%, #0284c7 100%);
  box-shadow: 0 4px 8px rgba(14, 165, 233, 0.3);
  transform: translateY(-1px);
}

.message-list {
  display: grid;
  align-content: start;
  gap: 0.65rem;
  min-height: 0;
  overflow-y: auto;
  border: 1px solid #334155;
  border-radius: 0.7rem;
  background: #111827;
  padding: 0.85rem;
}

.empty-state {
  margin: 0;
  color: #94a3b8;
  text-align: center;
}

.chat-error {
  display: grid;
  justify-items: start;
  gap: 0.35rem;
  color: #fecaca;
  overflow-wrap: anywhere;
}

.chat-error button {
  border: 1px solid #dc2626;
  border-radius: 0.45rem;
  background: #7f1d1d;
  color: #fff;
  cursor: pointer;
  padding: 0.4rem 0.65rem;
}

/* Backdrop */
.memory-panel-backdrop {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.5);
  backdrop-filter: blur(4px);
  z-index: 99;
  animation: fadeIn 0.2s ease-out;
}

/* Sidebar Drawer */
.memory-panel {
  position: fixed;
  top: 0;
  right: 0;
  bottom: 0;
  width: min(460px, 90vw);
  background: rgba(15, 23, 42, 0.9);
  backdrop-filter: blur(16px);
  border-left: 1px solid rgba(51, 65, 85, 0.8);
  box-shadow: -8px 0 32px rgba(0, 0, 0, 0.6);
  z-index: 100;
  display: flex;
  flex-direction: column;
  transform: translateX(100%);
  transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1);
}

.memory-panel.is-open {
  transform: translateX(0);
}

.memory-panel-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1.25rem 1.5rem;
  border-bottom: 1px solid #334155;
}

.memory-panel-header h2 {
  margin: 0;
  font-size: 1.25rem;
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

.close-btn:hover {
  color: #f8fafc;
}

.memory-panel-content {
  flex: 1;
  overflow-y: auto;
  padding: 1.5rem;
}

/* Loading state */
.loading-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 200px;
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
  to { transform: rotate(360deg); }
}

@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}

/* Empty state */
.empty-state-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  padding: 3rem 1.5rem;
  color: #94a3b8;
}

.empty-icon {
  font-size: 3rem;
  margin-bottom: 1rem;
}

.empty-state-container h3 {
  color: #f1f5f9;
  margin-bottom: 0.5rem;
}

.empty-state-container p {
  font-size: 0.9rem;
  line-height: 1.5;
  margin-bottom: 1.5rem;
}

.refresh-btn, .retry-btn {
  background: #334155;
  border: 1px solid #475569;
  color: #f1f5f9;
  padding: 0.5rem 1rem;
  border-radius: 0.375rem;
  cursor: pointer;
  transition: all 0.2s;
}

.refresh-btn:hover, .retry-btn:hover {
  background: #475569;
  border-color: #64748b;
}

/* Error state */
.error-state {
  background: rgba(239, 68, 68, 0.1);
  border: 1px solid rgba(239, 68, 68, 0.3);
  padding: 1.25rem;
  border-radius: 0.5rem;
  color: #fca5a5;
  margin-bottom: 1rem;
}

.error-title {
  font-weight: 600;
  margin-top: 0;
  margin-bottom: 0.5rem;
}

.error-code {
  font-family: monospace;
  font-size: 0.8rem;
  margin-bottom: 0.5rem;
  background: rgba(0, 0, 0, 0.2);
  padding: 0.15rem 0.3rem;
  border-radius: 0.25rem;
  display: inline-block;
}

.error-message {
  font-size: 0.9rem;
  line-height: 1.4;
  margin-bottom: 1rem;
}

/* Candidate list and cards */
.list-summary {
  font-size: 0.9rem;
  color: #94a3b8;
  margin-bottom: 1rem;
}

.candidate-card {
  background: rgba(30, 41, 59, 0.6);
  border: 1px solid rgba(71, 85, 105, 0.5);
  border-radius: 0.75rem;
  padding: 1.25rem;
  margin-bottom: 1.25rem;
  transition: all 0.2s ease;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
}

.candidate-card:hover {
  border-color: rgba(148, 163, 184, 0.5);
  box-shadow: 0 6px 12px rgba(0, 0, 0, 0.15);
}

.candidate-card.state-confirmed {
  border-color: rgba(16, 185, 129, 0.4);
  background: rgba(16, 185, 129, 0.03);
}

.card-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 1rem;
  flex-wrap: wrap;
}

.kind-select {
  background: #1e293b;
  border: 1px solid #475569;
  color: #f8fafc;
  padding: 0.25rem 0.5rem;
  border-radius: 0.375rem;
  font-size: 0.85rem;
  cursor: pointer;
  outline: none;
}

.kind-select:focus {
  border-color: #38bdf8;
}

.badge {
  font-size: 0.75rem;
  padding: 0.15rem 0.4rem;
  border-radius: 0.25rem;
  font-weight: 500;
}

.source-badge {
  background: #334155;
  color: #cbd5e1;
}

.sensitive-badge {
  background: rgba(249, 115, 22, 0.2);
  color: #fdba74;
  border: 1px solid rgba(249, 115, 22, 0.3);
}

.card-body {
  display: flex;
  flex-direction: column;
  gap: 0.85rem;
}

.input-label {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.input-label span {
  font-size: 0.75rem;
  color: #94a3b8;
  font-weight: 500;
}

.edit-textarea {
  background: #0f172a;
  border: 1px solid #334155;
  color: #f1f5f9;
  border-radius: 0.375rem;
  padding: 0.5rem;
  font-size: 0.875rem;
  font-family: inherit;
  resize: vertical;
  outline: none;
}

.edit-textarea:focus {
  border-color: #38bdf8;
}

.edit-textarea:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.metrics-row {
  display: flex;
  gap: 1rem;
  font-size: 0.75rem;
  color: #94a3b8;
}

/* Sensitive Warning and Consent */
.sensitive-consent-container {
  background: rgba(249, 115, 22, 0.08);
  border: 1px solid rgba(249, 115, 22, 0.25);
  border-radius: 0.5rem;
  padding: 0.75rem;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.sensitive-warning {
  font-size: 0.75rem;
  color: #fdba74;
  line-height: 1.4;
}

.checkbox-label {
  display: flex;
  align-items: flex-start;
  gap: 0.5rem;
  cursor: pointer;
  user-select: none;
  font-size: 0.8rem;
  color: #f1f5f9;
}

.checkbox-label input {
  margin-top: 0.15rem;
  cursor: pointer;
}

/* DB details */
.db-details {
  border-top: 1px solid #334155;
  padding-top: 0.75rem;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 0.5rem;
  font-size: 0.75rem;
  color: #94a3b8;
}

.db-id {
  font-family: monospace;
  background: rgba(0, 0, 0, 0.2);
  padding: 0.1rem 0.25rem;
  border-radius: 0.2rem;
  color: #cbd5e1;
}

.db-status-badge {
  font-weight: 600;
  text-transform: capitalize;
}

.db-status-badge.candidate {
  color: #38bdf8;
}

.db-status-badge.confirmed {
  color: #34d399;
}

/* Card error banner */
.card-error-banner {
  background: rgba(239, 68, 68, 0.08);
  border: 1px solid rgba(239, 68, 68, 0.25);
  border-radius: 0.5rem;
  padding: 0.75rem;
  color: #fca5a5;
  font-size: 0.8rem;
  line-height: 1.4;
}

.card-error-banner .error-header {
  font-weight: 600;
  margin-bottom: 0.25rem;
}

.card-error-banner code {
  background: rgba(0, 0, 0, 0.2);
  padding: 0.05rem 0.2rem;
  border-radius: 0.15rem;
}

/* Action buttons */
.card-actions {
  display: flex;
  gap: 0.5rem;
  margin-top: 1.25rem;
  flex-wrap: wrap;
  align-items: center;
}

.btn {
  cursor: pointer;
  border-radius: 0.375rem;
  font-size: 0.8rem;
  font-weight: 500;
  padding: 0.4rem 0.75rem;
  transition: all 0.2s ease;
  border: 1px solid transparent;
}

.btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
  transform: none !important;
  box-shadow: none !important;
}

.btn-primary {
  background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
  color: #ffffff;
  box-shadow: 0 2px 4px rgba(37, 99, 235, 0.25);
}

.btn-primary:hover:not(:disabled) {
  background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
  transform: translateY(-1px);
}

.btn-save {
  background: linear-gradient(135deg, #7c3aed 0%, #6d28d9 100%);
  color: #ffffff;
  box-shadow: 0 2px 4px rgba(124, 58, 237, 0.25);
}

.btn-save:hover:not(:disabled) {
  background: linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%);
  transform: translateY(-1px);
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

.btn-danger {
  background: transparent;
  border-color: #ef4444;
  color: #ef4444;
}

.btn-danger:hover:not(:disabled) {
  background: rgba(239, 68, 68, 0.1);
}

.confirmed-success-badge {
  font-size: 0.85rem;
  color: #34d399;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 0.25rem;
  animation: fadeIn 0.2s ease-out;
}

/* Alert warning banner styling */
.unconfirmed-warning-banner {
  background: rgba(249, 115, 22, 0.15);
  border: 1px solid rgba(249, 115, 22, 0.4);
  color: #fdba74;
  padding: 0.75rem 1rem;
  border-radius: 0.5rem;
  margin-bottom: 0.5rem;
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 0.9rem;
  animation: fadeIn 0.2s ease-out;
}

.close-banner-btn {
  background: none;
  border: none;
  color: #fdba74;
  font-size: 1.25rem;
  cursor: pointer;
  padding: 0 0.25rem;
  line-height: 1;
}

.close-banner-btn:hover {
  color: #f1f5f9;
}

/* Panel notice style */
.panel-notice-info {
  background: rgba(56, 189, 248, 0.08);
  border: 1px solid rgba(56, 189, 248, 0.25);
  color: #bae6fd;
  padding: 0.75rem;
  border-radius: 0.5rem;
  font-size: 0.8rem;
  line-height: 1.4;
  margin-bottom: 1rem;
}
</style>
