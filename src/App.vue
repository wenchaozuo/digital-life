<script setup lang="ts">
import { invoke } from "@tauri-apps/api/core";
import { onMounted, onUnmounted, ref } from "vue";
import { bodyStateMachine, defaultBodyProvider, type BodyState } from "./body";
import {
  ConversationError,
  conversationService,
  type ConversationResponse,
} from "./conversation";
import { initializeDefaultLife, type LifeIdentity } from "./life";
import type { ModelConfig } from "./model";
import { personaManager, type PersonaTemplate } from "./persona";
import { storageService } from "./storage";

const bodyState = ref<BodyState>("idle");
const bodyResource = ref("");
const lifeIdentity = ref<LifeIdentity>();
const personaTemplate = ref<PersonaTemplate>();
const settingsError = ref("");
const testEndpoint = ref("");
const testApiKey = ref("");
const testModelName = ref("");
const testInput = ref("");
const conversationResponse = ref<ConversationResponse>();
const conversationError = ref("");
const isSending = ref(false);
let unsubscribe: (() => void) | undefined;

async function openSettings(): Promise<void> {
  settingsError.value = "";

  try {
    await invoke("open_settings_window");
  } catch (error: unknown) {
    settingsError.value = error instanceof Error ? error.message : "Unable to open settings.";
  }
}

async function sendConversationTest(): Promise<void> {
  if (isSending.value) {
    return;
  }

  isSending.value = true;
  conversationResponse.value = undefined;
  conversationError.value = "";

  const modelConfig: ModelConfig = {
    baseUrl: testEndpoint.value,
    apiKey: testApiKey.value,
    modelName: testModelName.value,
  };

  try {
    conversationResponse.value = await conversationService.send({
      userInput: testInput.value,
      modelConfig,
      temperature: 0.7,
      maxTokens: 512,
    });
  } catch (error) {
    conversationError.value =
      error instanceof ConversationError
        ? `${error.code}: ${error.message}`
        : "CONVERSATION_MODEL_FAILED: The model request could not be completed.";
  } finally {
    isSending.value = false;
  }
}

onMounted(async () => {
  await storageService.initialize();
  lifeIdentity.value = await initializeDefaultLife();
  personaTemplate.value = await personaManager.getById(lifeIdentity.value.personaId);

  const body = await defaultBodyProvider.load(bodyStateMachine.getState());
  bodyState.value = body.state;
  bodyResource.value = body.resourcePath;

  unsubscribe = bodyStateMachine.subscribe(async ({ current }) => {
    const nextBody = await defaultBodyProvider.switchState(current);
    bodyState.value = nextBody.state;
    bodyResource.value = nextBody.resourcePath;
  });
});

onUnmounted(() => unsubscribe?.());
</script>

<template>
  <main class="desktop-body">
    <section class="body-card" aria-label="Digital Life desktop body">
      <button
        class="settings-button"
        type="button"
        aria-label="Open storage settings"
        title="Settings"
        @mousedown.stop
        @click.stop="openSettings"
      >
        ⚙
      </button>
      <img
        v-if="bodyResource"
        :src="bodyResource"
        :alt="`Digital Life ${bodyState} body`"
        class="body-image"
        draggable="false"
      />
      <div class="status" data-tauri-drag-region>
        <strong>{{ lifeIdentity?.name }}</strong>
        <span>Life ID: {{ lifeIdentity?.id }}</span>
        <span>Persona: {{ personaTemplate?.name }}</span>
        <span>Persona Version: {{ personaTemplate?.version }}</span>
        <span>State: {{ bodyState }}</span>
        <span v-if="settingsError" class="settings-error">{{ settingsError }}</span>
      </div>
      <details class="conversation-test">
        <summary>Conversation test</summary>
        <label>
          Endpoint
          <input v-model="testEndpoint" autocomplete="off" placeholder="Runtime only" />
        </label>
        <label>
          API key
          <input v-model="testApiKey" type="password" autocomplete="off" placeholder="Runtime only" />
        </label>
        <label>
          Model
          <input v-model="testModelName" autocomplete="off" placeholder="Model name" />
        </label>
        <label>
          Message
          <input v-model="testInput" autocomplete="off" placeholder="Type a test message" />
        </label>
        <button type="button" :disabled="isSending" @click="sendConversationTest">
          {{ isSending ? "Sending…" : "Send" }}
        </button>
        <p v-if="conversationResponse" class="conversation-result">
          <strong>You:</strong> {{ conversationResponse.userMessage.content }}
          <strong>Life:</strong> {{ conversationResponse.assistantMessage.content }}
        </p>
        <p v-if="conversationError" class="settings-error">{{ conversationError }}</p>
      </details>
    </section>
  </main>
</template>

<style>
:root {
  color: #f8fafc;
  background: transparent;
  font-family: Inter, ui-sans-serif, system-ui, sans-serif;
}

html,
body,
#app {
  width: 100%;
  min-width: 320px;
  min-height: 100%;
  margin: 0;
  background: transparent;
}

.desktop-body {
  display: grid;
  min-height: 100vh;
  place-items: center;
  user-select: none;
}

.body-card {
  position: relative;
  display: grid;
  justify-items: center;
  gap: 0.5rem;
  max-width: min(82vw, 340px);
  padding: 1rem;
}

.settings-button {
  position: absolute;
  z-index: 1;
  top: 0.25rem;
  right: 0.25rem;
  width: 2rem;
  height: 2rem;
  border: 1px solid rgb(255 255 255 / 32%);
  border-radius: 999px;
  background: rgb(15 23 42 / 82%);
  color: #e0f2fe;
  cursor: pointer;
  font-size: 1rem;
  line-height: 1;
}

.settings-button:hover,
.settings-button:focus-visible {
  background: rgb(14 116 144 / 92%);
}

.body-image {
  width: min(72vw, 300px);
  max-height: 470px;
  object-fit: contain;
  -webkit-user-drag: none;
}

.status {
  display: grid;
  gap: 0.15rem;
  padding: 0.45rem 0.75rem;
  border: 1px solid rgb(255 255 255 / 22%);
  border-radius: 0.75rem;
  background: rgb(15 23 42 / 78%);
  box-shadow: 0 8px 24px rgb(15 23 42 / 30%);
  text-align: center;
}

.status span {
  color: #b9f6ff;
  font-size: 0.875rem;
}

.status .settings-error {
  color: #fecaca;
}

.conversation-test {
  display: grid;
  width: min(82vw, 340px);
  gap: 0.5rem;
  color: #e0f2fe;
  font-size: 0.8rem;
}

.conversation-test summary {
  cursor: pointer;
  text-align: center;
}

.conversation-test[open] {
  padding: 0.65rem;
  border: 1px solid rgb(255 255 255 / 22%);
  border-radius: 0.75rem;
  background: rgb(15 23 42 / 78%);
}

.conversation-test label {
  display: grid;
  gap: 0.2rem;
}

.conversation-test input,
.conversation-test button {
  box-sizing: border-box;
  width: 100%;
  border: 1px solid rgb(255 255 255 / 32%);
  border-radius: 0.4rem;
  background: rgb(15 23 42 / 88%);
  color: #f8fafc;
  padding: 0.35rem 0.45rem;
}

.conversation-test button {
  cursor: pointer;
}

.conversation-test button:disabled {
  cursor: not-allowed;
  opacity: 0.6;
}

.conversation-result {
  display: grid;
  gap: 0.2rem;
  margin: 0;
  overflow-wrap: anywhere;
}
</style>
