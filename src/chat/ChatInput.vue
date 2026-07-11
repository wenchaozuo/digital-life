<script setup lang="ts">
import { ref } from "vue";

const props = defineProps<{
  disabled: boolean;
}>();

const emit = defineEmits<{
  send: [content: string];
}>();

const content = ref("");

function submit(): void {
  const value = content.value.trim();
  if (props.disabled || value.length === 0) {
    return;
  }

  emit("send", value);
  content.value = "";
}
</script>

<template>
  <form class="chat-input" @submit.prevent="submit">
    <textarea
      v-model="content"
      :disabled="disabled"
      placeholder="Type a message"
      rows="3"
      @keydown.enter.exact.prevent="submit"
    />
    <button type="submit" :disabled="disabled || content.trim().length === 0">
      {{ disabled ? "Sending…" : "Send" }}
    </button>
  </form>
</template>

<style scoped>
.chat-input {
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 0.65rem;
}

textarea,
button {
  font: inherit;
}

textarea {
  min-height: 3rem;
  resize: vertical;
  border: 1px solid #475569;
  border-radius: 0.55rem;
  background: #0f172a;
  color: #f8fafc;
  padding: 0.55rem;
}

button {
  align-self: end;
  border: 1px solid #0284c7;
  border-radius: 0.55rem;
  background: #0369a1;
  color: #f8fafc;
  cursor: pointer;
  padding: 0.55rem 0.85rem;
}

button:disabled,
textarea:disabled {
  cursor: not-allowed;
  opacity: 0.6;
}

@media (max-width: 620px) {
  .chat-input {
    grid-template-columns: 1fr;
  }

  button {
    justify-self: end;
  }
}
</style>
