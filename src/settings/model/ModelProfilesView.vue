<script setup lang="ts">
import { onMounted, onUnmounted, reactive, ref } from "vue";
import type { ModelProfile, ModelPurpose } from "../../model";
import ModelProfileCard from "./ModelProfileCard.vue";
import ModelProfileForm from "./ModelProfileForm.vue";
import {
  ModelProfileController,
  type ModelProfileDraft,
} from "./modelProfileController";

const props = defineProps<{ purpose: ModelPurpose }>();

const controller = reactive(new ModelProfileController(props.purpose));
const editingProfile = ref<ModelProfile>();
const formVisible = ref(false);
const formDirty = ref(false);
const clearEpoch = ref(0);

function openCreate(): void {
  editingProfile.value = undefined;
  formVisible.value = true;
  controller.formState = "editing";
  controller.formError = undefined;
}

function openEdit(profile: ModelProfile): void {
  editingProfile.value = profile;
  formVisible.value = true;
  controller.formState = "editing";
  controller.formError = undefined;
}

function closeForm(): void {
  clearSensitiveInputs();
  formVisible.value = false;
  editingProfile.value = undefined;
  formDirty.value = false;
  controller.formState = "idle";
}

function requestCloseForm(): void {
  if (formDirty.value && !window.confirm("Discard unsaved model profile changes?")) {
    return;
  }
  closeForm();
}

async function saveProfile(draft: ModelProfileDraft): Promise<void> {
  const saved = await controller.saveProfile(draft, editingProfile.value?.id);
  if (saved) {
    closeForm();
  }
}

async function testConnection(profileId: string): Promise<void> {
  await controller.testConnection(profileId);
}

function clearSensitiveInputs(): void {
  clearEpoch.value += 1;
}

function requestLeave(): boolean {
  if (formDirty.value && !window.confirm("Discard unsaved model profile changes?")) {
    return false;
  }
  clearSensitiveInputs();
  closeForm();
  return true;
}

function onVisibilityChange(): void {
  if (document.visibilityState === "hidden") {
    clearSensitiveInputs();
  }
}

onMounted(() => {
  void controller.refresh();
  document.addEventListener("visibilitychange", onVisibilityChange);
});

onUnmounted(() => {
  document.removeEventListener("visibilitychange", onVisibilityChange);
  clearSensitiveInputs();
});

defineExpose({ clearSensitiveInputs, requestLeave });
</script>

<template>
  <section class="model-profiles-view" :aria-label="purpose === 'chat' ? 'Chat model profiles' : 'Embedding model profiles'">
    <header class="model-header">
      <div>
        <h2>{{ purpose === "chat" ? "Conversation models" : "Embedding models" }}</h2>
        <p>Each profile has an independent API Key stored only in Windows Credential Manager.</p>
      </div>
      <button type="button" class="primary" @click="openCreate">Create profile</button>
    </header>

    <p class="active-summary">
      Current profile: {{ controller.activeProfile?.profileId ?? "Not selected" }}
    </p>

    <ModelProfileForm
      v-if="formVisible"
      :purpose="purpose"
      :profile="editingProfile"
      :saving="controller.formState === 'savingProfile'"
      :error-message="controller.formError?.message"
      @submit="saveProfile"
      @request-close="requestCloseForm"
      @dirty-change="formDirty = $event"
    />

    <section v-if="controller.listState === 'loading'" class="empty-state">Loading profiles…</section>
    <section v-else-if="controller.listState === 'failed'" class="empty-state error" role="alert">
      <strong>{{ controller.listError?.code }}</strong>
      <p>{{ controller.listError?.message }}</p>
      <button type="button" @click="controller.refresh">Retry</button>
    </section>
    <section v-else-if="controller.profiles.length === 0" class="empty-state">
      <strong>No {{ purpose }} profiles yet.</strong>
      <p>Create one when you are ready. No default profile is created automatically.</p>
    </section>
    <div v-else class="profile-list">
      <ModelProfileCard
        v-for="profile in controller.profiles"
        :key="`${profile.id}-${clearEpoch}`"
        :profile="profile"
        :active="controller.activeProfile?.profileId === profile.id"
        :runtime="controller.cardState(profile.id)"
        :clear-epoch="clearEpoch"
        :on-save-credential="controller.saveCredential.bind(controller)"
        :on-delete-credential="controller.deleteCredential.bind(controller)"
        :on-set-active="controller.setActive.bind(controller)"
        :on-test-connection="testConnection"
        :on-delete-profile="controller.deleteProfile.bind(controller)"
        @edit="openEdit"
      />
    </div>
  </section>
</template>

<style scoped>
.model-profiles-view, .profile-list { display: grid; gap: 1rem; }
.model-header { display: flex; gap: 1rem; align-items: start; justify-content: space-between; }
h2, p { margin: 0; }
.model-header p, .active-summary { color: #cbd5e1; }
.primary { border-color: #0284c7; background: #0369a1; }
.empty-state { display: grid; gap: 0.5rem; border: 1px dashed #475569; border-radius: 0.7rem; color: #cbd5e1; padding: 1rem; }
.error { border-color: #dc2626; color: #fecaca; }
@media (max-width: 620px) { .model-header { align-items: stretch; flex-direction: column; } }
</style>
