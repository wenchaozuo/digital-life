<script setup lang="ts">
import { onMounted, onUnmounted, reactive, ref, computed } from "vue";
import type { ModelProfile, ModelPurpose } from "../../model";
import ModelProfileCard from "./ModelProfileCard.vue";
import ModelProfileForm from "./ModelProfileForm.vue";
import MemoryVectorIndexPanel from "./MemoryVectorIndexPanel.vue";
import MemoryVectorSyncPanel from "./MemoryVectorSyncPanel.vue";
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

interface MemoryVectorIndexPanelHandle {
  refreshStatus(): void;
  notifyActiveEmbeddingProfileChanged(): void;
  deactivate(): void;
  isRebuildRunning: boolean;
  status: any;
}
const memoryVectorIndexPanel = ref<MemoryVectorIndexPanelHandle>();

interface MemoryVectorSyncPanelHandle {
  refreshStatus(): void;
  deactivate(): void;
  isSyncRunning: boolean;
  status: any;
  settings: any;
}
const memoryVectorSyncPanel = ref<MemoryVectorSyncPanelHandle>();

const rebuildRunning = computed(() => memoryVectorIndexPanel.value?.isRebuildRunning ?? false);
const syncRunning = computed(() => memoryVectorSyncPanel.value?.isSyncRunning ?? false);

function refreshMemoryVectorIndexStatus(): void {
  if (props.purpose === "embedding") {
    memoryVectorIndexPanel.value?.refreshStatus();
    memoryVectorSyncPanel.value?.refreshStatus();
  }
}

function notifyActiveEmbeddingProfileChanged(): void {
  if (props.purpose === "embedding") {
    memoryVectorIndexPanel.value?.notifyActiveEmbeddingProfileChanged();
    memoryVectorSyncPanel.value?.refreshStatus();
  }
}

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
  const updatedActiveProfile = editingProfile.value?.id === controller.activeProfile?.profileId;
  const saved = await controller.saveProfile(draft, editingProfile.value?.id);
  if (saved) {
    closeForm();
    if (updatedActiveProfile) {
      notifyActiveEmbeddingProfileChanged();
    } else {
      refreshMemoryVectorIndexStatus();
    }
  }
}

async function testConnection(profileId: string): Promise<void> {
  await controller.testConnection(profileId);
}

function clearSensitiveInputs(): void {
  clearEpoch.value += 1;
}

async function saveCredential(profileId: string, apiKey: string): Promise<boolean> {
  const saved = await controller.saveCredential(profileId, apiKey);
  if (saved) {
    refreshMemoryVectorIndexStatus();
  }
  return saved;
}

async function deleteCredential(profileId: string): Promise<boolean> {
  const deleted = await controller.deleteCredential(profileId);
  if (deleted) {
    refreshMemoryVectorIndexStatus();
  }
  return deleted;
}

async function setActive(profileId: string): Promise<boolean> {
  const activated = await controller.setActive(profileId);
  if (activated) {
    notifyActiveEmbeddingProfileChanged();
  }
  return activated;
}

async function deleteProfile(profileId: string): Promise<boolean> {
  const deletedActiveProfile = profileId === controller.activeProfile?.profileId;
  const deleted = await controller.deleteProfile(profileId);
  if (deleted) {
    if (deletedActiveProfile) {
      notifyActiveEmbeddingProfileChanged();
    } else {
      refreshMemoryVectorIndexStatus();
    }
  }
  return deleted;
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
  memoryVectorIndexPanel.value?.deactivate();
  memoryVectorSyncPanel.value?.deactivate();
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

    <div v-if="purpose === 'embedding'" class="embedding-summary">
      <h4>状态摘要</h4>
      <ul>
        <li>Active Profile: {{ memoryVectorIndexPanel?.status?.activeEmbeddingProfileExists ? 'Yes' : 'No' }}</li>
        <li>Credential Saved: {{ memoryVectorIndexPanel?.status?.credentialExists ? 'Yes' : 'No' }}</li>
        <li>Index Established: {{ memoryVectorIndexPanel?.status?.indexDirectoryExists ? 'Yes' : 'No' }}</li>
        <li>Eligible Memories: {{ memoryVectorIndexPanel?.status?.eligibleMemoryCount ?? 0 }}</li>
        <li>Indexed Memories: {{ memoryVectorIndexPanel?.status?.indexedCount ?? 0 }}</li>
        <li>Sync Enabled: {{ memoryVectorSyncPanel?.settings?.enabled ? 'Yes' : 'No' }}</li>
        <li>Pending Syncs: {{ memoryVectorSyncPanel?.status?.pendingCount ?? 0 }}</li>
        <li>Blocked/Failed Syncs: {{ (memoryVectorSyncPanel?.status?.blockedCount ?? 0) + (memoryVectorSyncPanel?.status?.failedCount ?? 0) }}</li>
      </ul>
      <div class="suggestions">
        <strong>建议: </strong>
        <span v-if="!memoryVectorIndexPanel?.status?.activeEmbeddingProfileExists">请设置活动模型档案。</span>
        <span v-else-if="!memoryVectorIndexPanel?.status?.credentialExists">请为活动模型配置 API 凭据。</span>
        <span v-else-if="!memoryVectorIndexPanel?.status?.indexDirectoryExists">请执行全量重建。</span>
        <span v-else-if="memoryVectorSyncPanel?.status?.blockedCount || memoryVectorSyncPanel?.status?.failedCount">请检查凭据或配置并重试失败项。</span>
        <span v-else-if="memoryVectorSyncPanel?.status?.pendingCount && !memoryVectorSyncPanel?.settings?.enabled">有待同步的项，建议启用同步或手动重建。</span>
        <span v-else>状态正常。</span>
      </div>
    </div>

    <ModelProfileForm
      v-if="formVisible"
      :purpose="purpose"
      :profile="editingProfile"
      :saving="controller.formState === 'savingProfile'"
      :error-message="controller.formError?.safeMessage"
      @submit="saveProfile"
      @request-close="requestCloseForm"
      @dirty-change="formDirty = $event"
    />

    <section v-if="controller.listState === 'loading'" class="empty-state">Loading profiles…</section>
    <section v-else-if="controller.listState === 'failed'" class="empty-state error" role="alert">
      <strong>{{ controller.listError?.code }}</strong>
      <p>{{ controller.listError?.safeMessage }}</p>
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
        :on-save-credential="saveCredential"
        :on-delete-credential="deleteCredential"
        :on-set-active="setActive"
        :on-test-connection="testConnection"
        :on-delete-profile="deleteProfile"
        @edit="openEdit"
      />
    </div>

    <div v-if="purpose === 'embedding'" class="index-section">
      <MemoryVectorIndexPanel
        ref="memoryVectorIndexPanel"
        :sync-running="syncRunning"
      />
      <MemoryVectorSyncPanel
        ref="memoryVectorSyncPanel"
        :rebuild-running="rebuildRunning"
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
.embedding-summary { border: 1px solid #475569; padding: 1rem; border-radius: 0.7rem; background: #1e293b; color: #cbd5e1; }
.embedding-summary ul { list-style: none; padding: 0; display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; margin: 0.5rem 0; }
.embedding-summary .suggestions { color: #38bdf8; margin-top: 0.5rem; }
.index-section { display: grid; gap: 1rem; }
@media (max-width: 620px) { .model-header { align-items: stretch; flex-direction: column; } .embedding-summary ul { grid-template-columns: 1fr; } }
</style>
