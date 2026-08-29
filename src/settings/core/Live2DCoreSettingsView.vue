<script setup lang="ts">
import { open } from "@tauri-apps/plugin-dialog";
import { computed, onMounted, ref } from "vue";

import {
  coreSettingsErrorFromUnknown,
  coreStatusLabel,
  isExactLive2DCoreFilePath,
  live2dCoreSettingsService,
  type Live2DCoreSettingsError,
  type ManagedCubismCoreSnapshot,
} from "./live2dCoreSettingsService";

const snapshot = ref<ManagedCubismCoreSnapshot>();
const error = ref<Live2DCoreSettingsError>();
const operation = ref("");
const loading = ref(false);
const installSucceeded = ref(false);

const statusLabel = computed(() => coreStatusLabel(snapshot.value?.status));
const restartRequiredLabel = computed(() =>
  snapshot.value?.restartRequired ? "Yes" : "No",
);

async function refresh(): Promise<void> {
  loading.value = true;
  error.value = undefined;
  try {
    snapshot.value = await live2dCoreSettingsService.getSnapshot();
  } catch (caught) {
    error.value = coreSettingsErrorFromUnknown(caught);
  } finally {
    loading.value = false;
  }
}

async function installCore(): Promise<void> {
  error.value = undefined;
  operation.value = "";
  installSucceeded.value = false;
  let transientSourcePath: string | null = null;
  try {
    const selected = await open({
      title: "Install Cubism Core",
      directory: false,
      multiple: false,
      filters: [{ name: "Cubism Core", extensions: ["js"] }],
    });
    if (typeof selected !== "string" || selected.length === 0) {
      return;
    }
    transientSourcePath = selected;
    if (!isExactLive2DCoreFilePath(transientSourcePath)) {
      error.value = coreSettingsErrorFromUnknown({
        code: "LIVE2D_CORE_INVALID_INPUT",
      });
      return;
    }

    loading.value = true;
    operation.value = "Installing Cubism Core…";
    snapshot.value = await live2dCoreSettingsService.install(transientSourcePath);
    installSucceeded.value = true;
    operation.value = "Cubism Core installed.";
  } catch (caught) {
    error.value = coreSettingsErrorFromUnknown(caught);
  } finally {
    // The selected absolute path is a one-operation input only. It is never
    // retained in reactive state or rendered by Settings.
    transientSourcePath = null;
    loading.value = false;
  }
}

onMounted(() => {
  void refresh();
});
</script>

<template>
  <section class="settings-section core-settings" aria-label="Live2D Core settings">
    <section class="result" aria-label="Live2D Core status">
      <h2>Live2D Core</h2>
      <dl>
        <div>
          <dt>Status</dt>
          <dd data-testid="live2d-core-status">{{ statusLabel }}</dd>
        </div>
        <div>
          <dt>Verified version</dt>
          <dd data-testid="live2d-core-version">{{ snapshot?.versionLabel ?? "Not configured" }}</dd>
        </div>
        <div>
          <dt>Restart required</dt>
          <dd data-testid="live2d-core-restart-required">{{ restartRequiredLabel }}</dd>
        </div>
        <div v-if="snapshot?.sha256">
          <dt>Verified SHA-256</dt>
          <dd><code data-testid="live2d-core-sha256">{{ snapshot.sha256 }}</code></dd>
        </div>
      </dl>
    </section>

    <div class="actions">
      <button
        type="button"
        class="primary"
        data-testid="install-cubism-core"
        :disabled="loading"
        @click="installCore"
      >
        Install Cubism Core
      </button>
      <button type="button" data-testid="refresh-cubism-core" :disabled="loading" @click="refresh">
        Refresh status
      </button>
    </div>

    <p v-if="operation" class="phase" role="status">{{ operation }}</p>

    <section v-if="installSucceeded" class="result success" aria-label="Cubism Core installed">
      <strong>Verified Cubism Core installed.</strong>
      <p>A full application exit and restart is required before Main can load it.</p>
    </section>

    <section v-if="error" class="result error" aria-live="polite">
      <strong>{{ error.code }}</strong>
      <p>{{ error.message }}</p>
    </section>

    <p class="core-note">
      Settings only installs and reports the managed Core. Main loads the verified Core after restart.
    </p>
  </section>
</template>

<style scoped>
.core-settings { display: grid; gap: 1rem; }
.core-settings dl { display: grid; gap: 0.6rem; margin: 0; }
.core-settings dl div { display: grid; gap: 0.2rem; }
.core-settings dt { color: #94a3b8; font-size: 0.85rem; }
.core-settings dd { margin: 0; }
.core-settings .actions { display: flex; flex-wrap: wrap; gap: 0.65rem; }
.core-note { color: #cbd5e1; font-size: 0.9rem; }
</style>
