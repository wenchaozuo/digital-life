<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from "vue";
import type { ModelProfile } from "../../model";
import type { ProfileCardRuntimeState } from "./modelProfileController";

const props = defineProps<{
  profile: ModelProfile;
  active: boolean;
  runtime: ProfileCardRuntimeState;
  clearEpoch: number;
  onSaveCredential: (profileId: string, apiKey: string) => Promise<boolean>;
  onDeleteCredential: (profileId: string) => Promise<boolean>;
  onSetActive: (profileId: string) => Promise<boolean>;
  onTestConnection: (profileId: string) => Promise<void>;
  onDeleteProfile: (profileId: string) => Promise<boolean>;
}>();

const emit = defineEmits<{ edit: [profile: ModelProfile] }>();

const apiKeyInput = ref("");
const showKey = ref(false);
const localMessage = ref("");
const busy = computed(() =>
  ["savingCredential", "deletingCredential", "settingActive", "testingConnection", "deletingProfile"].includes(props.runtime.state),
);

watch(
  () => props.clearEpoch,
  () => clearSensitiveInput(),
);

onUnmounted(clearSensitiveInput);

function clearSensitiveInput(): void {
  apiKeyInput.value = "";
  showKey.value = false;
  localMessage.value = "";
}

async function saveCredential(): Promise<void> {
  localMessage.value = "";
  if (apiKeyInput.value.trim().length === 0) {
    localMessage.value = "Enter an API Key before saving.";
    return;
  }
  if (await props.onSaveCredential(props.profile.id, apiKeyInput.value)) {
    clearSensitiveInput();
  }
}

async function deleteCredential(): Promise<void> {
  if (!window.confirm("Delete the saved API Key for this profile? This cannot be undone.")) {
    return;
  }
  await props.onDeleteCredential(props.profile.id);
}

async function deleteProfile(): Promise<void> {
  if (!window.confirm("Delete this model profile? Delete its API Key first if one is saved.")) {
    return;
  }
  await props.onDeleteProfile(props.profile.id);
}
</script>

<template>
  <article class="model-profile-card">
    <header>
      <div>
        <h3>{{ profile.displayName }}</h3>
        <p>{{ profile.providerKind }}</p>
      </div>
      <span v-if="active" class="active-badge">Current</span>
    </header>

    <dl>
      <div><dt>Base URL</dt><dd>{{ profile.baseUrl }}</dd></div>
      <div><dt>Model</dt><dd>{{ profile.modelName }}</dd></div>
      <div v-if="profile.purpose === 'chat'"><dt>Temperature</dt><dd>{{ profile.temperature }}</dd></div>
      <div v-if="profile.purpose === 'chat'"><dt>Max tokens</dt><dd>{{ profile.maxTokens }}</dd></div>
      <div v-if="profile.purpose === 'embedding'"><dt>Embedding dimension</dt><dd>{{ profile.embeddingDimension }}</dd></div>
    </dl>

    <section class="credential-section" aria-label="Credential controls">
      <strong>API Key: {{ runtime.credentialExists ? "Saved" : "Not saved" }}</strong>
      <div class="credential-row">
        <input
          v-model="apiKeyInput"
          :type="showKey ? 'text' : 'password'"
          autocomplete="new-password"
          placeholder="Enter a new API Key"
          :disabled="busy"
        />
        <button type="button" :disabled="busy" @click="showKey = !showKey">
          {{ showKey ? "Hide" : "Show" }}
        </button>
        <button type="button" class="primary" :disabled="busy" @click="saveCredential">Save / replace</button>
      </div>
      <div class="actions">
        <button type="button" :disabled="busy || !runtime.credentialExists" @click="deleteCredential">Delete API Key</button>
      </div>
      <p v-if="localMessage" class="card-error">{{ localMessage }}</p>
    </section>

    <div class="actions">
      <button type="button" :disabled="busy" @click="emit('edit', profile)">Edit</button>
      <button type="button" :disabled="busy || active" @click="onSetActive(profile.id)">Set as current</button>
      <button type="button" :disabled="busy || !runtime.credentialExists" @click="onTestConnection(profile.id)">
        {{ runtime.state === "testingConnection" ? "Testing…" : "Test connection" }}
      </button>
      <button type="button" class="danger" :disabled="busy" @click="deleteProfile">Delete profile</button>
    </div>

    <section v-if="runtime.connectionTest" class="test-result" :class="runtime.connectionTest.success ? 'success' : 'error'">
      <strong>{{ runtime.connectionTest.success ? "Connection succeeded" : "Connection failed" }}</strong>
      <p>Latency: {{ runtime.connectionTest.latencyMs }} ms</p>
      <p>Provider: {{ runtime.connectionTest.providerKind ?? profile.providerKind }}</p>
      <p>Model: {{ runtime.connectionTest.modelName ?? profile.modelName }}</p>
      <p v-if="runtime.connectionTest.embeddingDimension">Dimension: {{ runtime.connectionTest.embeddingDimension }}</p>
      <p v-if="runtime.connectionTest.errorCode">{{ runtime.connectionTest.errorCode }}: {{ runtime.connectionTest.errorMessage }}</p>
    </section>
    <section v-if="runtime.error" class="card-error" role="alert">
      <strong>{{ runtime.error.code }}</strong>
      <p>{{ runtime.error.safeMessage }}</p>
    </section>
  </article>
</template>

<style scoped>
.model-profile-card { display: grid; gap: 0.75rem; border: 1px solid #334155; border-radius: 0.7rem; background: #172033; padding: 1rem; }
header, .credential-row, .actions { display: flex; gap: 0.6rem; align-items: center; }
header { justify-content: space-between; }
h3, p { margin: 0; }
header p, dt { color: #94a3b8; font-size: 0.85rem; }
.active-badge { border-radius: 999px; background: #166534; color: #dcfce7; padding: 0.2rem 0.5rem; font-size: 0.8rem; }
dl { display: grid; gap: 0.35rem; margin: 0; }
dl div { display: grid; grid-template-columns: 10rem minmax(0, 1fr); gap: 0.5rem; }
dd { margin: 0; overflow-wrap: anywhere; color: #bae6fd; }
.credential-section { display: grid; gap: 0.55rem; border-top: 1px solid #334155; border-bottom: 1px solid #334155; padding: 0.75rem 0; }
input { min-width: 0; flex: 1; border: 1px solid #475569; border-radius: 0.4rem; background: #0f172a; color: #f8fafc; padding: 0.5rem; }
.primary { border-color: #0284c7; background: #0369a1; }
.danger { border-color: #dc2626; background: #991b1b; }
.test-result { display: grid; gap: 0.35rem; border: 1px solid #475569; border-radius: 0.45rem; padding: 0.7rem; }
.success { border-color: #15803d; }
.error, .card-error { color: #fecaca; }
@media (max-width: 620px) { .credential-row, .actions { flex-wrap: wrap; } dl div { grid-template-columns: 1fr; } }
</style>
