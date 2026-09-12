<script setup lang="ts">
import { open } from "@tauri-apps/plugin-dialog";
import { invoke } from "@tauri-apps/api/core";
import { computed, onMounted, onUnmounted, ref } from "vue";
import { lifeIdentityManager } from "../../life";

interface VitaStartResponse {
  sessionId: string;
  ready: boolean;
}

interface VitaPendingSummary {
  pendingId: string;
  capabilityId: string;
  workspaceSummary: string;
  expiresAtUnixMs: number;
}

interface VitaStatus {
  running: boolean;
  providerReadiness: string;
  capabilityReadiness: string;
  capabilityStates: Array<{
    capabilityId: string;
    readiness: string;
    revision: number | null;
  }>;
  sessionLifeId: string | null;
  currentLifeId: string | null;
  sessionId: string | null;
  pending: VitaPendingSummary | null;
  activeTurnId: string | null;
  turnPhase: string | null;
  assistantText: string | null;
  turnError: string | null;
}

const workspacePath = ref("");
const prompt = ref("");
const status = ref<VitaStatus>({
  running: false,
  providerReadiness: "SIDECAR_NOT_RUNNING",
  capabilityReadiness: "AUTHORIZATION_UNAVAILABLE",
  capabilityStates: [],
  sessionLifeId: null,
  currentLifeId: null,
  sessionId: null,
  pending: null,
  activeTurnId: null,
  turnPhase: null,
  assistantText: null,
  turnError: null,
});
const busy = ref(false);
const error = ref<string>();
let pollTimer: ReturnType<typeof setInterval> | undefined;

const turnActive = computed(() => status.value.activeTurnId !== null);
const cancelling = computed(() => status.value.turnPhase === "CANCELLING");
const pendingConfirmation = computed(() => status.value.pending);
const capabilityBlocksTurn = computed(() => [
  "ROOT_DISABLED",
  "AUTHORIZATION_MISSING",
  "AUTHORIZATION_UNAVAILABLE",
  "LIFE_RESTART_REQUIRED",
].includes(status.value.capabilityReadiness));

async function refreshStatus(): Promise<void> {
  try {
    status.value = await invoke<VitaStatus>("get_vita_sidecar_status");
  } catch (caught) {
    error.value = boundedError(caught, "Vita status is unavailable.");
  }
}

async function chooseWorkspace(): Promise<void> {
  const selected = await open({
    title: "Choose the workspace for Vita Git status",
    directory: true,
    multiple: false,
  });
  if (typeof selected === "string") {
    workspacePath.value = selected;
  }
}

async function ensureSession(): Promise<boolean> {
  if (status.value.running) return true;
  const life = await lifeIdentityManager.getCurrent();
  if (!life || workspacePath.value.trim().length === 0) {
    error.value = "Choose a workspace before starting Vita.";
    return false;
  }
  const response = await invoke<VitaStartResponse>("start_vita_sidecar", {
    request: {
      lifeId: life.id,
      taskId: crypto.randomUUID(),
      workspacePath: workspacePath.value.trim(),
    },
  });
  if (!response.ready) {
    error.value = "Vita sidecar did not become ready.";
    return false;
  }
  await refreshStatus();
  return status.value.running;
}

async function startTurn(): Promise<void> {
  if (busy.value || turnActive.value || prompt.value.trim().length === 0) return;
  busy.value = true;
  error.value = undefined;
  try {
    await refreshStatus();
    if (capabilityBlocksTurn.value) {
      error.value = capabilityMessage(status.value.capabilityReadiness);
      return;
    }
    if (!status.value.running && ["NO_ACTIVE_PROFILE", "CREDENTIAL_MISSING", "INELIGIBLE_URL"].includes(status.value.providerReadiness)) {
      error.value = readinessMessage(status.value.providerReadiness);
      return;
    }
    if (status.value.running && status.value.providerReadiness === "SIDECAR_RESTART_REQUIRED") {
      error.value = "The active Chat profile changed. Stop and restart Vita before starting a turn.";
      return;
    }
    if (!(await ensureSession())) return;
    await invoke("start_vita_turn", { request: { prompt: prompt.value } });
    prompt.value = "";
    await refreshStatus();
  } catch (caught) {
    const value = boundedError(caught, "Vita turn could not start.");
    const lifeChanged = value === "CAPABILITY_RUNTIME_LIFE_CHANGED" || value === "SIDECAR_LIFE_RESTART_REQUIRED";
    const capabilityError = capabilityErrorMessage(value);
    error.value = capabilityError ?? value;
    if (lifeChanged) {
      await refreshStatus();
    }
  } finally {
    busy.value = false;
  }
}

async function cancelTurn(): Promise<void> {
  if (busy.value || !turnActive.value || cancelling.value) return;
  try {
    await invoke("cancel_vita_turn");
    await refreshStatus();
  } catch (caught) {
    error.value = boundedError(caught, "Vita turn could not be cancelled.");
  }
}

async function decidePending(pendingId: string, command: "confirm_vita_sidecar" | "deny_vita_sidecar"): Promise<void> {
  try {
    await invoke(command, { pendingId });
    await refreshStatus();
  } catch (caught) {
    error.value = boundedError(caught, "The pending Vita confirmation is no longer available.");
  }
}

async function stopSession(): Promise<void> {
  try {
    await invoke("stop_vita_sidecar");
    await refreshStatus();
  } catch (caught) {
    error.value = boundedError(caught, "Vita sidecar could not stop.");
  }
}

function boundedError(caught: unknown, fallback: string): string {
  const value = typeof caught === "string" ? caught : caught instanceof Error ? caught.message : "";
  return (value || fallback).slice(0, 256);
}

function readinessMessage(readiness: string): string {
  if (readiness === "NO_ACTIVE_PROFILE") return "Choose an eligible active Chat profile before starting Vita.";
  if (readiness === "CREDENTIAL_MISSING") return "Add a credential to the active Chat profile before starting Vita.";
  if (readiness === "INELIGIBLE_URL") return "Vita requires an HTTPS public provider endpoint.";
  return "Vita is not ready to start a turn.";
}

function capabilityMessage(readiness: string): string {
  if (readiness === "ROOT_DISABLED") return "Enable the governed Git status capability in Agent permissions.";
  if (readiness === "AUTHORIZATION_MISSING") return "Open Agent permissions to provision the governed Git status capability.";
  if (readiness === "LIFE_RESTART_REQUIRED") return "Current Life changed. Stop and restart Vita to bind the current Life.";
  return "The governed Git status capability is unavailable. Review Agent permissions before starting Vita.";
}

function capabilityErrorMessage(value: string): string | undefined {
  if (value === "CAPABILITY_RUNTIME_LIFE_CHANGED" || value === "SIDECAR_LIFE_RESTART_REQUIRED") {
    return capabilityMessage("LIFE_RESTART_REQUIRED");
  }
  if (value === "CAPABILITY_ROOT_DISABLED") return capabilityMessage("ROOT_DISABLED");
  if (value === "CAPABILITY_AUTHORIZATION_REQUIRED") return capabilityMessage("AUTHORIZATION_MISSING");
  if (value === "CAPABILITY_AUTHORIZATION_UNAVAILABLE") return capabilityMessage("AUTHORIZATION_UNAVAILABLE");
  return undefined;
}

function capabilityLabel(readiness: string): string {
  if (readiness === "ROOT_ENABLED") return "Enabled";
  if (readiness === "ROOT_DISABLED") return "Disabled";
  if (readiness === "LIFE_RESTART_REQUIRED") return "Restart required";
  if (readiness === "AUTHORIZATION_MISSING") return "Authorization missing";
  return "Unavailable";
}

onMounted(() => {
  void refreshStatus();
  pollTimer = setInterval(() => void refreshStatus(), 750);
});

onUnmounted(() => {
  if (pollTimer !== undefined) clearInterval(pollTimer);
});
</script>

<template>
  <section class="vita-turn-panel" aria-label="Vita Agent turn">
    <header>
      <div>
        <h3>Vita Agent turn</h3>
        <p>Uses the active Chat profile. Credentials stay in Windows Credential Manager.</p>
      </div>
      <span class="vita-state" :class="{ ready: status.running }">
        {{ status.running ? (status.turnPhase ?? "ready") : status.providerReadiness }}
      </span>
    </header>

    <p class="vita-capability" data-testid="vita-capability-readiness">
      Capability root: {{ capabilityLabel(status.capabilityReadiness) }}
    </p>
    <p v-if="status.capabilityReadiness === 'ROOT_DISABLED' || status.capabilityReadiness === 'AUTHORIZATION_MISSING'" class="vita-error">
      {{ capabilityMessage(status.capabilityReadiness) }}
    </p>
    <p v-else-if="status.capabilityReadiness === 'LIFE_RESTART_REQUIRED'" class="vita-error">
      {{ capabilityMessage(status.capabilityReadiness) }}
    </p>

    <p v-if="status.providerReadiness === 'INELIGIBLE_URL'" class="vita-error">
      Vita production mode requires an HTTPS public provider endpoint; this profile can still be used elsewhere.
    </p>
    <p v-else-if="status.providerReadiness === 'CREDENTIAL_MISSING'" class="vita-error">
      Add a credential to the active Chat profile before starting Vita.
    </p>
    <p v-else-if="status.providerReadiness === 'SIDECAR_RESTART_REQUIRED'" class="vita-error">
      The active Chat profile changed. Stop and restart Vita to bind the new provider.
    </p>

    <label class="field-label" for="vita-workspace">Workspace</label>
    <div class="vita-input-row">
      <input id="vita-workspace" v-model="workspacePath" :disabled="status.running" autocomplete="off" placeholder="Choose a workspace folder" />
      <button type="button" :disabled="status.running" @click="chooseWorkspace">Choose folder</button>
    </div>

    <label class="field-label" for="vita-prompt">Turn prompt</label>
    <textarea id="vita-prompt" v-model="prompt" rows="3" maxlength="65536" placeholder="Ask Vita to inspect the governed workspace status" />

    <div class="vita-actions">
      <button type="button" class="primary" :disabled="busy || turnActive || capabilityBlocksTurn || prompt.trim().length === 0" @click="startTurn">
        {{ busy ? "Starting…" : "Start Vita turn" }}
      </button>
      <button type="button" :disabled="!turnActive || cancelling" @click="cancelTurn">{{ cancelling ? "Cancelling…" : "Cancel turn" }}</button>
      <button type="button" :disabled="!status.running" @click="stopSession">Stop sidecar</button>
    </div>

    <section v-if="pendingConfirmation" class="vita-confirmation" aria-live="polite">
      <strong>Confirmation required</strong>
      <p>{{ pendingConfirmation.capabilityId }} · {{ pendingConfirmation.workspaceSummary }}</p>
      <p>Expires {{ new Date(pendingConfirmation.expiresAtUnixMs).toLocaleTimeString() }}</p>
      <div class="vita-actions">
        <button type="button" class="primary" @click="decidePending(pendingConfirmation.pendingId, 'confirm_vita_sidecar')">Confirm</button>
        <button type="button" @click="decidePending(pendingConfirmation.pendingId, 'deny_vita_sidecar')">Deny</button>
      </div>
    </section>

    <p v-if="status.assistantText" class="vita-output" aria-live="polite">{{ status.assistantText }}</p>
    <p v-if="status.turnError" class="vita-error" role="alert">{{ status.turnError }}</p>
    <p v-if="error" class="vita-error" role="alert">{{ error }}</p>
  </section>
</template>

<style scoped>
.vita-turn-panel { display: grid; gap: 0.75rem; border: 1px solid #475569; border-radius: 0.7rem; padding: 1rem; background: #111c2e; }
.vita-turn-panel header { display: flex; justify-content: space-between; gap: 1rem; align-items: start; }
.vita-turn-panel h3, .vita-turn-panel p { margin: 0; }
.vita-turn-panel header p { color: #cbd5e1; font-size: 0.9rem; }
.vita-state { color: #94a3b8; font-size: 0.85rem; }
.vita-state.ready { color: #67e8f9; }
.field-label { color: #cbd5e1; font-size: 0.9rem; }
.vita-input-row { display: flex; gap: 0.5rem; }
.vita-input-row input, .vita-turn-panel textarea { width: 100%; box-sizing: border-box; border: 1px solid #475569; border-radius: 0.45rem; background: #0f172a; color: #f8fafc; padding: 0.55rem; }
.vita-actions { display: flex; flex-wrap: wrap; gap: 0.5rem; }
.vita-confirmation { display: grid; gap: 0.4rem; border: 1px solid #f59e0b; border-radius: 0.5rem; padding: 0.75rem; color: #fde68a; }
.vita-output { white-space: pre-wrap; max-height: 16rem; overflow: auto; border-left: 3px solid #22d3ee; padding-left: 0.75rem; }
.vita-error { color: #fecaca; }
@media (max-width: 620px) { .vita-turn-panel header, .vita-input-row { flex-direction: column; align-items: stretch; } }
</style>
