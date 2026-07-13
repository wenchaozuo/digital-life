<script setup lang="ts">
import type { ConversationSummary } from "../conversation";

const props = defineProps<{
  conversations: readonly ConversationSummary[];
  selectedConversationId?: string;
  disabled: boolean;
  loading: boolean;
}>();

const emit = defineEmits<{
  create: [];
  select: [conversation: ConversationSummary];
  delete: [conversation: ConversationSummary];
}>();

function formatUpdatedAt(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function select(conversation: ConversationSummary): void {
  if (!props.disabled && conversation.id !== props.selectedConversationId) {
    emit("select", conversation);
  }
}
</script>

<template>
  <aside class="conversation-sidebar" aria-label="Conversations">
    <div class="sidebar-header">
      <h2>会话</h2>
      <button type="button" :disabled="disabled" @click="emit('create')">新建</button>
    </div>

    <p v-if="loading" class="sidebar-status" aria-live="polite">正在加载会话…</p>
    <p v-else-if="conversations.length === 0" class="sidebar-status">还没有会话</p>

    <ul v-else class="conversation-list">
      <!-- Keep the repository order: it is the authoritative recent-session order. -->
      <li v-for="conversation in conversations" :key="conversation.id">
        <button
          type="button"
          class="conversation-item"
          :class="{ selected: conversation.id === selectedConversationId }"
          :disabled="disabled"
          :aria-current="conversation.id === selectedConversationId ? 'page' : undefined"
          @click="select(conversation)"
        >
          <span class="conversation-item-title">{{ conversation.title }}</span>
          <span class="conversation-item-time">{{ formatUpdatedAt(conversation.updatedAt) }}</span>
        </button>
        <button
          v-if="conversation.id === selectedConversationId"
          type="button"
          class="delete-conversation"
          :disabled="disabled"
          :aria-label="`删除会话：${conversation.title}`"
          @click="emit('delete', conversation)"
        >
          删除
        </button>
      </li>
    </ul>
  </aside>
</template>

<style scoped>
.conversation-sidebar {
  display: grid;
  align-content: start;
  gap: 0.75rem;
  min-height: 0;
  overflow-y: auto;
  border: 1px solid #334155;
  border-radius: 0.7rem;
  background: #111827;
  padding: 0.75rem;
}

.sidebar-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
}

.sidebar-header h2,
.sidebar-status {
  margin: 0;
}

.sidebar-header button,
.delete-conversation {
  border: 1px solid #475569;
  border-radius: 0.4rem;
  background: #1e293b;
  color: #e2e8f0;
  cursor: pointer;
  padding: 0.35rem 0.55rem;
}

.conversation-list {
  display: grid;
  gap: 0.45rem;
  margin: 0;
  padding: 0;
  list-style: none;
}

.conversation-list li {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 0.35rem;
}

.conversation-item {
  display: grid;
  gap: 0.2rem;
  min-width: 0;
  border: 1px solid #334155;
  border-radius: 0.45rem;
  background: #0f172a;
  color: #e2e8f0;
  cursor: pointer;
  padding: 0.5rem;
  text-align: left;
}

.conversation-item.selected {
  border-color: #38bdf8;
  background: #0c4a6e;
}

.conversation-item-title,
.conversation-item-time {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.conversation-item-time,
.sidebar-status {
  color: #94a3b8;
  font-size: 0.75rem;
}

.delete-conversation {
  align-self: center;
  border-color: #7f1d1d;
  color: #fecaca;
}

button:disabled {
  cursor: not-allowed;
  opacity: 0.55;
}
</style>
