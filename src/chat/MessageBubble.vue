<script setup lang="ts">
import type { ConversationMessage } from "../conversation";

defineProps<{
  message: ConversationMessage;
}>();
</script>

<template>
  <article class="message-bubble" :class="`message-${message.role}`">
    <strong>{{ message.role }}</strong>
    <p>{{ message.content }}</p>
    <time>{{ new Date(message.timestamp).toLocaleTimeString() }}</time>
  </article>
</template>

<style scoped>
.message-bubble {
  display: grid;
  gap: 0.35rem;
  max-width: 82%;
  padding: 0.7rem 0.85rem;
  border: 1px solid #475569;
  border-radius: 0.75rem;
  overflow-wrap: anywhere;
}

.message-bubble p {
  margin: 0;
  white-space: pre-wrap;
}

.message-bubble time {
  color: #94a3b8;
  font-size: 0.75rem;
}

.message-user {
  justify-self: end;
  border-color: #0284c7;
  background: #0c4a6e;
}

.message-assistant {
  justify-self: start;
  background: #1e293b;
}

.message-system {
  justify-self: center;
  border-style: dashed;
  background: #172033;
  color: #cbd5e1;
}
</style>
