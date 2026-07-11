<script setup lang="ts">
import { open } from "@tauri-apps/plugin-dialog";
import { invoke } from "@tauri-apps/api/core";
import { computed, onMounted, ref } from "vue";
import {
  storageService,
  type StorageLocationInfo,
  type StorageLocationValidation,
  type StorageMigrationResult,
} from "../storage";
import {
  canInteractWithLocation,
  canStartMigration,
  errorFromMigration,
  errorFromUnknown,
  errorFromValidation,
  isDirectorySelectionCancelled,
  type StorageSettingsError,
  type StorageSettingsPhase,
} from "./settingsState";

const currentLocation = ref<StorageLocationInfo>();
const candidateDirectory = ref("");
const validation = ref<StorageLocationValidation>();
const migration = ref<StorageMigrationResult>();
const phase = ref<StorageSettingsPhase>("unselected");
const error = ref<StorageSettingsError>();
const confirmationVisible = ref(false);

const canInteract = computed(() => canInteractWithLocation(phase.value));
const canMigrate = computed(() =>
  canStartMigration(phase.value, candidateDirectory.value),
);

async function refreshCurrentLocation(): Promise<void> {
  currentLocation.value = await storageService.getStorageLocation();
}

function clearCandidateResult(): void {
  validation.value = undefined;
  migration.value = undefined;
  error.value = undefined;
  confirmationVisible.value = false;
}

function updateCandidate(value: string): void {
  if (!canInteract.value) {
    return;
  }

  candidateDirectory.value = value;
  clearCandidateResult();
  phase.value = value.trim().length > 0 ? "selected" : "unselected";
}

async function chooseDirectory(): Promise<void> {
  if (!canInteract.value) {
    return;
  }

  try {
    const selected = await open({
      title: "Choose data root directory",
      directory: true,
      multiple: false,
    });

    if (isDirectorySelectionCancelled(selected)) {
      return;
    }

    updateCandidate(selected);
  } catch (caught) {
    error.value = errorFromUnknown(caught);
  }
}

async function validateDirectory(): Promise<void> {
  if (!canInteract.value || candidateDirectory.value.trim().length === 0) {
    return;
  }

  phase.value = "validating";
  error.value = undefined;
  migration.value = undefined;

  try {
    const result = await storageService.validateStorageLocation(candidateDirectory.value);
    validation.value = result;
    error.value = errorFromValidation(result);
    phase.value = result.isValid ? "validated" : "validationFailed";
  } catch (caught) {
    error.value = errorFromUnknown(caught);
    phase.value = "validationFailed";
  }
}

function showMigrationConfirmation(): void {
  if (!canMigrate.value) {
    return;
  }

  confirmationVisible.value = true;
  phase.value = "awaitingConfirmation";
}

function cancelMigrationConfirmation(): void {
  if (phase.value !== "awaitingConfirmation") {
    return;
  }

  confirmationVisible.value = false;
  phase.value = "validated";
}

async function confirmMigration(): Promise<void> {
  if (phase.value !== "awaitingConfirmation") {
    return;
  }

  confirmationVisible.value = false;
  phase.value = "migrating";
  error.value = undefined;

  try {
    const result = await storageService.migrateStorageLocation(candidateDirectory.value);
    migration.value = result;
    error.value = errorFromMigration(result);

    if (!result.success) {
      phase.value = "migrationFailed";
      return;
    }

    await refreshCurrentLocation();
    phase.value = "migrationSucceeded";
  } catch (caught) {
    error.value = errorFromUnknown(caught);
    phase.value = "migrationFailed";
  }
}

function closeSettings(): void {
  if (phase.value !== "migrating") {
    void invoke("close_settings_window");
  }
}

onMounted(async () => {
  try {
    await refreshCurrentLocation();
  } catch (caught) {
    error.value = errorFromUnknown(caught);
  }
});
</script>

<template>
  <main class="settings-page">
    <section class="settings-panel" aria-labelledby="settings-title">
      <header>
        <p class="eyebrow">Digital Life</p>
        <h1 id="settings-title">Storage location</h1>
        <p>Choose and safely migrate the local SQLite data root.</p>
      </header>

      <section class="location-summary" aria-label="Current storage location">
        <h2>Current data root</h2>
        <code>{{ currentLocation?.currentDirectory ?? "Loading…" }}</code>
        <p>
          {{ currentLocation?.isDefaultDirectory ? "Using the default application directory." : "Using a custom data directory." }}
        </p>
      </section>

      <label class="field-label" for="candidate-directory">New data root</label>
      <div class="directory-input-row">
        <input
          id="candidate-directory"
          :value="candidateDirectory"
          :disabled="!canInteract"
          autocomplete="off"
          placeholder="Choose or enter an absolute folder path"
          @input="updateCandidate(($event.target as HTMLInputElement).value)"
        />
        <button type="button" :disabled="!canInteract" @click="chooseDirectory">
          Choose folder
        </button>
      </div>

      <div class="actions">
        <button
          type="button"
          :disabled="!canInteract || candidateDirectory.trim().length === 0"
          @click="validateDirectory"
        >
          {{ phase === "validating" ? "Validating…" : "Validate directory" }}
        </button>
        <button type="button" class="primary" :disabled="!canMigrate" @click="showMigrationConfirmation">
          Migrate data
        </button>
      </div>

      <p class="phase" role="status">Status: {{ phase }}</p>

      <section v-if="validation" class="result" :class="validation.isValid ? 'success' : 'error'">
        <strong>{{ validation.isValid ? "Directory validated" : "Directory validation failed" }}</strong>
        <code>{{ validation.candidateDirectory }}</code>
      </section>

      <section v-if="confirmationVisible" class="confirmation" aria-label="Migration confirmation">
        <h2>Confirm SQLite migration</h2>
        <dl>
          <div><dt>Original directory</dt><dd>{{ currentLocation?.currentDirectory }}</dd></div>
          <div><dt>New directory</dt><dd>{{ candidateDirectory }}</dd></div>
        </dl>
        <p>SQLite data will be copied and switched to the new directory. The original database will not be deleted automatically.</p>
        <p>Do not close the application during migration. A restart may be required depending on the backend result.</p>
        <div class="actions">
          <button type="button" @click="cancelMigrationConfirmation">Cancel</button>
          <button type="button" class="danger" @click="confirmMigration">Confirm migration</button>
        </div>
      </section>

      <section v-if="migration?.success" class="result success" aria-label="Migration success">
        <strong>Migration completed</strong>
        <p>Original directory: {{ migration.oldDirectory }}</p>
        <p>New directory: {{ migration.newDirectory }}</p>
        <p>Active directory: {{ currentLocation?.currentDirectory }}</p>
        <p>Original database retained: {{ migration.originalDatabaseRetained ? "Yes" : "No" }}</p>
        <p>Restart required: {{ migration.restartRequired ? "Yes" : "No" }}</p>
      </section>

      <section v-if="error" class="result error" aria-live="polite">
        <strong>{{ error.code }}</strong>
        <p>{{ error.message }}</p>
        <p v-if="error.failedStage">Failed stage: {{ error.failedStage }}</p>
        <p>The original database remains available.</p>
      </section>

      <footer>
        <button type="button" :disabled="phase === 'migrating'" @click="closeSettings">
          Close settings
        </button>
      </footer>
    </section>
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

button {
  border: 1px solid #475569;
  border-radius: 0.45rem;
  background: #1e293b;
  color: #f8fafc;
  cursor: pointer;
  padding: 0.55rem 0.8rem;
}

button:hover:not(:disabled),
button:focus-visible:not(:disabled) {
  border-color: #38bdf8;
  background: #334155;
}

button:disabled,
input:disabled {
  cursor: not-allowed;
  opacity: 0.55;
}

.settings-page {
  min-height: 100vh;
  box-sizing: border-box;
  padding: 1.5rem;
}

.settings-panel {
  display: grid;
  gap: 1rem;
  max-width: 760px;
  margin: 0 auto;
}

h1,
h2,
p {
  margin: 0;
}

h1 { font-size: 1.6rem; }
h2 { font-size: 1rem; }

.eyebrow { color: #7dd3fc; font-size: 0.8rem; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; }

header,
.location-summary,
.result,
.confirmation {
  display: grid;
  gap: 0.6rem;
  border: 1px solid #334155;
  border-radius: 0.75rem;
  background: #172033;
  padding: 1rem;
}

code,
dd {
  overflow-wrap: anywhere;
  color: #bae6fd;
}

.field-label { font-weight: 700; }

.directory-input-row,
.actions {
  display: flex;
  gap: 0.65rem;
}

.directory-input-row input { min-width: 0; flex: 1; border: 1px solid #475569; border-radius: 0.45rem; background: #0f172a; color: #f8fafc; padding: 0.55rem 0.7rem; }
.primary { border-color: #0284c7; background: #0369a1; }
.danger { border-color: #dc2626; background: #991b1b; }
.phase { color: #cbd5e1; font-size: 0.9rem; }
.success { border-color: #15803d; }
.error { border-color: #dc2626; color: #fecaca; }
.confirmation { border-color: #f59e0b; }
dl { display: grid; gap: 0.5rem; margin: 0; }
dl div { display: grid; gap: 0.2rem; }
dt { color: #94a3b8; font-size: 0.85rem; }
footer { display: flex; justify-content: flex-end; }

@media (max-width: 620px) {
  .settings-page { padding: 1rem; }
  .directory-input-row,
  .actions { flex-direction: column; }
}
</style>
