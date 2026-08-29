<script setup lang="ts">
import { open } from "@tauri-apps/plugin-dialog";
import { computed, onMounted, ref } from "vue";
import {
  bodyPackageService,
  type InstalledBodyPackageSnapshot,
} from "../../body";
import { storageService } from "../../storage";
import type { LifeIdentity } from "../../life";

const packages = ref<InstalledBodyPackageSnapshot[]>([]);
const currentLife = ref<LifeIdentity>();
const loading = ref(false);
const operation = ref("");
const error = ref("");
const pendingImportPath = ref("");
const pendingImportDisplayName = ref("");

const currentBodyId = computed(() => currentLife.value?.bodyId ?? "unknown");

function errorMessage(caught: unknown): string {
  if (typeof caught === "object" && caught !== null) {
    const candidate = caught as { code?: unknown; message?: unknown };
    if (typeof candidate.code === "string" && typeof candidate.message === "string") {
      return `${candidate.code}: ${candidate.message}`;
    }
    if (typeof candidate.message === "string") {
      return candidate.message;
    }
  }
  return caught instanceof Error ? caught.message : "Body operation failed.";
}

function displayNameForPath(sourcePath: string): string {
  const filename = sourcePath.replace(/^.*[\\/]/, "");
  return filename.replace(/\.model3\.json$/i, "") || "Imported Live2D body";
}

function isCurrent(bodyId: string): boolean {
  return currentLife.value?.bodyId === bodyId;
}

async function refresh(): Promise<void> {
  loading.value = true;
  error.value = "";
  try {
    const [listedPackages, life] = await Promise.all([
      bodyPackageService.list(),
      storageService.getCurrentLife(),
    ]);
    packages.value = listedPackages;
    currentLife.value = life;
  } catch (caught) {
    error.value = errorMessage(caught);
  } finally {
    loading.value = false;
  }
}

async function chooseImport(): Promise<void> {
  error.value = "";
  operation.value = "";
  try {
    const selected = await open({
      title: "Import Live2D body",
      directory: false,
      multiple: false,
      filters: [{ name: "Live2D model", extensions: ["model3.json"] }],
    });
    if (typeof selected !== "string" || selected.length === 0) {
      return;
    }

    pendingImportPath.value = selected;
    pendingImportDisplayName.value = displayNameForPath(selected);
  } catch (caught) {
    error.value = errorMessage(caught);
  }
}

function cancelImport(): void {
  pendingImportPath.value = "";
  pendingImportDisplayName.value = "";
  operation.value = "";
}

async function importBody(): Promise<void> {
  error.value = "";
  if (pendingImportPath.value.length === 0) {
    await chooseImport();
    return;
  }
  if (pendingImportDisplayName.value.trim().length === 0) {
    error.value = "Enter a display name for the body.";
    return;
  }

  operation.value = "Importing body…";
  const sourcePath = pendingImportPath.value;
  const displayName = pendingImportDisplayName.value.trim();
  try {
    await bodyPackageService.install({
      sourcePath,
      displayName,
    });
    await refresh();
    operation.value = "Body imported.";
  } catch (caught) {
    error.value = errorMessage(caught);
  } finally {
    pendingImportPath.value = "";
    pendingImportDisplayName.value = "";
    if (operation.value === "Importing body…") {
      operation.value = "";
    }
  }
}

async function setBody(bodyId: string): Promise<void> {
  error.value = "";
  operation.value = "Applying body…";
  try {
    currentLife.value = await bodyPackageService.setCurrentBody(bodyId);
    await refresh();
    operation.value = "Body applied.";
  } catch (caught) {
    error.value = errorMessage(caught);
    operation.value = "";
  }
}

async function deleteBody(bodyId: string): Promise<void> {
  error.value = "";
  operation.value = "Removing body…";
  try {
    await bodyPackageService.delete(bodyId);
    await refresh();
    operation.value = "Body removed.";
  } catch (caught) {
    error.value = errorMessage(caught);
    operation.value = "";
  }
}

onMounted(() => {
  void refresh();
});
</script>

<template>
  <section class="settings-section body-settings" aria-label="Body settings">
    <section class="body-current result" aria-label="Current body">
      <h2>Current body</h2>
      <code data-testid="current-body-id">{{ currentBodyId }}</code>
      <p>
        {{ currentBodyId === "default-png" ? "Bundled PNG body" : "Managed body package" }}
      </p>
    </section>

    <section class="result" aria-label="Body actions">
      <div class="body-action-row">
        <div>
          <h2>Installed bodies</h2>
          <p>Import a validated local model package or return to the bundled body.</p>
        </div>
        <button type="button" class="primary" :disabled="loading" @click="importBody">
          Choose model3.json
        </button>
      </div>
      <div v-if="pendingImportPath" class="import-draft" aria-label="Body import details">
        <label for="body-display-name">Display name</label>
        <input id="body-display-name" v-model="pendingImportDisplayName" data-testid="pending-display-name" />
        <div class="actions">
          <button type="button" class="primary" :disabled="loading" @click="importBody">Import body</button>
          <button type="button" :disabled="loading" @click="cancelImport">Cancel</button>
        </div>
      </div>
      <p v-if="operation" class="phase" role="status">{{ operation }}</p>
    </section>

    <section class="body-list" aria-label="Installed body packages">
      <article class="body-package result" data-testid="default-body-package">
        <div>
          <h3>Bundled PNG body</h3>
          <code>default-png</code>
          <p>Always available fallback presentation.</p>
        </div>
        <div class="actions">
          <button type="button" :disabled="isCurrent('default-png') || loading" @click="setBody('default-png')">
            {{ isCurrent("default-png") ? "Current body" : "Use this body" }}
          </button>
        </div>
      </article>

      <article
        v-for="bodyPackage in packages"
        :key="bodyPackage.bodyId"
        class="body-package result"
        :data-testid="`body-package-${bodyPackage.bodyId}`"
      >
        <div>
          <h3>{{ bodyPackage.displayName }}</h3>
          <code>{{ bodyPackage.bodyId }}</code>
          <p>Status: {{ bodyPackage.status }}</p>
          <p>Installed version: {{ bodyPackage.packageVersion }}</p>
        </div>
        <div class="actions">
          <button
            type="button"
            :disabled="bodyPackage.status !== 'available' || isCurrent(bodyPackage.bodyId) || loading"
            @click="setBody(bodyPackage.bodyId)"
          >
            {{ isCurrent(bodyPackage.bodyId) ? "Current body" : "Use this body" }}
          </button>
          <button type="button" class="danger" :disabled="loading" @click="deleteBody(bodyPackage.bodyId)">
            Delete
          </button>
        </div>
      </article>

      <p v-if="packages.length === 0" class="phase">No managed body packages installed.</p>
    </section>

    <section v-if="error" class="result error" aria-live="polite">
      <strong>Body operation failed</strong>
      <p>{{ error }}</p>
      <p>The current Life body selection was not changed by this failed operation.</p>
    </section>
  </section>
</template>

<style scoped>
.body-settings { display: grid; gap: 1rem; }
.body-action-row { display: flex; align-items: center; justify-content: space-between; gap: 1rem; }
.body-list { display: grid; gap: 0.75rem; }
.body-package { display: flex; align-items: center; justify-content: space-between; gap: 1rem; }
.body-package h3 { margin: 0 0 0.35rem; font-size: 1rem; }
.body-package p { margin: 0.25rem 0 0; }
.body-action-row h2 { margin-bottom: 0.35rem; }
.body-action-row p { color: #cbd5e1; }
.import-draft { display: grid; gap: 0.5rem; margin-top: 0.75rem; }
.import-draft input { border: 1px solid #475569; border-radius: 0.45rem; background: #0f172a; color: #f8fafc; padding: 0.55rem 0.7rem; }
.actions { display: flex; flex-wrap: wrap; justify-content: flex-end; }

@media (max-width: 620px) {
  .body-action-row,
  .body-package { align-items: stretch; flex-direction: column; }
  .body-package .actions { justify-content: flex-start; }
}
</style>
