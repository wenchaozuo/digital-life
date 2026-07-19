<script setup lang="ts">
import { computed, ref, watch } from "vue";
import type { ModelProfile, ModelPurpose } from "../../model";
import {
  isDraftValid,
  type ModelProfileDraft,
} from "./modelProfileController";

const props = defineProps<{
  purpose: ModelPurpose;
  profile?: ModelProfile;
  saving: boolean;
  errorMessage?: string;
}>();

const emit = defineEmits<{
  submit: [draft: ModelProfileDraft];
  requestClose: [];
  dirtyChange: [dirty: boolean];
}>();



const displayName = ref(props.profile?.displayName ?? "");
const baseUrl = ref(props.profile?.baseUrl ?? "");
const modelName = ref(props.profile?.modelName ?? "");
const temperature = ref(props.profile?.temperature ?? (props.purpose === "candidate_extraction" ? 0.0 : 0.7));
const maxTokens = ref(props.profile?.maxTokens ?? (props.purpose === "candidate_extraction" ? 2048 : 4096));
const embeddingDimension = ref(props.profile?.embeddingDimension ?? 1536);

const initialSnapshot = snapshot();
const draft = computed<ModelProfileDraft>(() => {
  if (props.purpose === "chat") {
    return {
      purpose: "chat",
      displayName: displayName.value,
      baseUrl: baseUrl.value,
      modelName: modelName.value,
      temperature: Number(temperature.value),
      maxTokens: Number(maxTokens.value),
    };
  } else if (props.purpose === "embedding") {
    return {
      purpose: "embedding",
      displayName: displayName.value,
      baseUrl: baseUrl.value,
      modelName: modelName.value,
      embeddingDimension: Number(embeddingDimension.value),
    };
  } else {
    return {
      purpose: "candidate_extraction",
      displayName: displayName.value,
      baseUrl: baseUrl.value,
      modelName: modelName.value,
      maxTokens: Number(maxTokens.value),
    };
  }
});

const isValid = computed(() => isDraftValid(draft.value));
const isDirty = computed(() => snapshot() !== initialSnapshot);

watch(isDirty, (dirty) => emit("dirtyChange", dirty), { immediate: true });

function snapshot(): string {
  return JSON.stringify({
    displayName: displayName.value,
    baseUrl: baseUrl.value,
    modelName: modelName.value,
    temperature: temperature.value,
    maxTokens: maxTokens.value,
    embeddingDimension: embeddingDimension.value,
  });
}

function submit(): void {
  if (!isValid.value || props.saving) {
    return;
  }
  emit("submit", draft.value);
}
</script>

<template>
  <section class="model-profile-form" :aria-label="profile ? 'Edit model profile' : 'Create model profile'">
    <header>

      <h3>{{ profile ? "Edit" : "Create" }} {{ purpose === "chat" ? "chat" : purpose === "embedding" ? "embedding" : "candidate extraction" }} profile</h3>
      <p>Profile settings do not contain an API Key.</p>
    </header>

    <label>
      Display name
      <input v-model="displayName" autocomplete="off" maxlength="128" />
    </label>
    <label>
      Base URL
      <input v-model="baseUrl" inputmode="url" autocomplete="url" placeholder="https://provider.example/v1" />
    </label>
    <label>
      Model name
      <input v-model="modelName" autocomplete="off" maxlength="256" />
    </label>



    <template v-if="purpose === 'chat'">
      <label>
        Temperature
        <input v-model.number="temperature" type="number" min="0" max="2" step="0.1" />
      </label>
      <label>
        Max tokens
        <input v-model.number="maxTokens" type="number" min="1" max="1000000" step="1" />
      </label>
    </template>
    <template v-else-if="purpose === 'candidate_extraction'">
      <label>
        Temperature (Fixed)
        <input type="number" value="0.0" disabled />
      </label>
      <label>
        Max tokens
        <input v-model.number="maxTokens" type="number" min="1" max="4096" step="1" />
      </label>
    </template>
    <label v-else-if="purpose === 'embedding'">
      Embedding dimension
      <input v-model.number="embeddingDimension" type="number" min="1" max="65536" step="1" />
    </label>
    <p v-if="!isValid" class="form-warning">Enter a valid HTTP or HTTPS URL and all required values.</p>
    <p v-if="errorMessage" class="form-error">{{ errorMessage }}</p>
    <div class="form-actions">
      <button type="button" :disabled="saving" @click="emit('requestClose')">Cancel</button>
      <button type="button" class="primary" :disabled="saving || !isValid" @click="submit">
        {{ saving ? "Saving…" : "Save profile" }}
      </button>
    </div>
  </section>
</template>

<style scoped>
.model-profile-form { display: grid; gap: 0.7rem; border: 1px solid #0e7490; border-radius: 0.7rem; background: #132a3a; padding: 1rem; }
header, label { display: grid; gap: 0.35rem; }
h3, p { margin: 0; }
label { color: #cbd5e1; font-weight: 650; }
input { border: 1px solid #475569; border-radius: 0.4rem; background: #0f172a; color: #f8fafc; padding: 0.5rem; }
.form-actions { display: flex; gap: 0.6rem; justify-content: flex-end; }
.primary { border-color: #0284c7; background: #0369a1; }
.form-warning { color: #fbbf24; }
.form-error { color: #fecaca; }
</style>
