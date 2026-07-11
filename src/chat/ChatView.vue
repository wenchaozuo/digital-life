<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import { bodyStateMachine, type BodyState } from "../body";
import {
  ConversationError,
  conversationService,
  type ConversationMessage,
} from "../conversation";
import type { ModelConfig } from "../model";
import ChatInput from "./ChatInput.vue";
import MessageBubble from "./MessageBubble.vue";

const bodyState = ref<BodyState>(bodyStateMachine.getState());
const messages = ref<readonly ConversationMessage[]>([]);
const endpoint = ref("");
const apiKey = ref("");
const modelName = ref("");
const error = ref("");
const isSending = ref(false);
const showSystemMessages = ref(false);
const visibleMessages = computed(() =>
  messages.value.filter(
    (message) => message.role !== "system" || showSystemMessages.value,
  ),
);

let unsubscribeMessages: (() => void) | undefined;
let unsubscribeBodyState: (() => void) | undefined;

function refreshMessages(): void {
  messages.value = conversationService.getSession().getMessages();
}

async function send(content: string): Promise<void> {
  if (isSending.value) {
    return;
  }

  isSending.value = true;
  error.value = "";
  const modelConfig: ModelConfig = {
    baseUrl: endpoint.value,
    apiKey: apiKey.value,
    modelName: modelName.value,
  };

  try {
    await conversationService.send({
      userInput: content,
      modelConfig,
      temperature: 0.7,
      maxTokens: 512,
    });
  } catch (caught) {
    error.value =
      caught instanceof ConversationError
        ? `${caught.code}: ${caught.message}`
        : "CONVERSATION_MODEL_FAILED: The model request could not be completed.";
  } finally {
    refreshMessages();
    isSending.value = false;
  }
}

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

    <details class="runtime-config">
      <summary>Runtime model configuration</summary>
      <label>Endpoint<input v-model="endpoint" autocomplete="off" placeholder="Runtime only" /></label>
      <label>API key<input v-model="apiKey" type="password" autocomplete="off" placeholder="Runtime only" /></label>
      <label>Model<input v-model="modelName" autocomplete="off" placeholder="Model name" /></label>
    </details>

    <button class="system-toggle" type="button" @click="showSystemMessages = !showSystemMessages">
      {{ showSystemMessages ? "Hide system messages" : "Show system messages" }}
    </button>

    <section class="message-list" aria-label="Conversation messages">
      <p v-if="visibleMessages.length === 0" class="empty-state">No messages in this runtime session.</p>
      <MessageBubble
        v-for="(message, index) in visibleMessages"
        v-else
        :key="`${message.timestamp}-${index}`"
        :message="message"
      />
    </section>

    <p v-if="error" class="chat-error">{{ error }}</p>
    <ChatInput :disabled="isSending" @send="send" />
  </main>
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
  grid-template-rows: auto auto auto minmax(0, 1fr) auto auto;
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

.runtime-config {
  display: grid;
  gap: 0.55rem;
  border: 1px solid #334155;
  border-radius: 0.7rem;
  background: #172033;
  padding: 0.7rem;
}

.runtime-config summary,
.system-toggle {
  cursor: pointer;
}

.runtime-config label {
  display: grid;
  gap: 0.25rem;
}

.runtime-config input {
  border: 1px solid #475569;
  border-radius: 0.45rem;
  background: #0f172a;
  color: #f8fafc;
  padding: 0.45rem;
}

.system-toggle {
  justify-self: start;
  border: 1px solid #475569;
  border-radius: 0.45rem;
  background: #1e293b;
  color: #e2e8f0;
  padding: 0.4rem 0.6rem;
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
  margin: 0;
  color: #fecaca;
  overflow-wrap: anywhere;
}
</style>
