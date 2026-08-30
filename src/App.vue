<script setup lang="ts">
import { invoke } from "@tauri-apps/api/core";
import { computed, onMounted, onUnmounted, ref } from "vue";
import {
  BodyBindingChangedListenerLifecycle,
  BodyExpressionListenerLifecycle,
  BodyRuntimeBindingController,
  bodyBindingChangedBridge,
  bodyExpressionBridge,
  bodyStateMachine,
  bodyPackageService,
  createBodyPresentationForBodyId,
  installManagedBodyPackageRegistrySnapshot,
  type BodyState,
} from "./body";
import { initializeDefaultLife, type LifeIdentity } from "./life";
import { personaManager, type PersonaTemplate } from "./persona";
import {
  mainScreenObservationService,
  screenObservationErrorFromUnknown,
  type MainScreenObservation,
  type MainScreenObservationError,
  type MainScreenPerceptionStatus,
} from "./perception/screenObservationService";
import { storageService } from "./storage";

const bodyState = ref<BodyState>("idle");
const bodyRendererElement = ref<HTMLElement>();
const lifeIdentity = ref<LifeIdentity>();
const personaTemplate = ref<PersonaTemplate>();
const settingsError = ref("");
const screenPerceptionStatus = ref<MainScreenPerceptionStatus>();
const screenObservation = ref<MainScreenObservation>();
const screenObservationError = ref<MainScreenObservationError>();
const screenObservationLoading = ref(false);
let unsubscribe: (() => void) | undefined;
let bodyRuntimeBinding: BodyRuntimeBindingController | undefined;
let lifecycleEpoch = 0;
let screenStatusRequestGeneration = 0;

const screenReadinessLabel = computed(() => {
  if (screenObservationLoading.value) {
    return "Observing";
  }
  const status = screenPerceptionStatus.value;
  if (status === undefined || !status.consentEnabled) {
    return "Needs setup";
  }
  if (!status.sessionArmed) {
    return "Disarmed";
  }
  if (!status.targetSelected) {
    return "No target";
  }
  return status.ready ? "Ready" : "Not ready";
});

const canObserveScreen = computed(
  () =>
    lifeIdentity.value !== undefined &&
    screenPerceptionStatus.value?.ready === true &&
    !screenObservationLoading.value,
);

// D17-C: the listener registration race with unmount is fenced by this
// controller, so a registration promise resolving after unmount is
// immediately unlistened.
const bodyExpressionListener = new BodyExpressionListenerLifecycle((handler) =>
  bodyExpressionBridge.listenForBodyExpression(handler),
);
const bodyBindingChangedListener = new BodyBindingChangedListenerLifecycle((handler) =>
  bodyBindingChangedBridge.listen(handler),
);

async function openSettings(): Promise<void> {
  settingsError.value = "";

  try {
    await invoke("open_settings_window");
  } catch (error: unknown) {
    settingsError.value = error instanceof Error ? error.message : "Unable to open settings.";
  }
}

async function openChat(): Promise<void> {
  settingsError.value = "";
  try {
    await invoke("open_chat_window");
  } catch (error) {
    settingsError.value = error instanceof Error ? error.message : "Unable to open chat.";
  }
}

function clearScreenObservation(): void {
  screenObservation.value = undefined;
  screenObservationError.value = undefined;
}

async function refreshScreenPerceptionStatus(
  lifeId: string,
  runtimeEpoch: number,
): Promise<void> {
  const requestGeneration = ++screenStatusRequestGeneration;
  try {
    const status = await mainScreenObservationService.getStatus(lifeId);
    if (
      !isRuntimeActive(runtimeEpoch) ||
      requestGeneration !== screenStatusRequestGeneration ||
      lifeIdentity.value?.id !== lifeId
    ) {
      return;
    }
    screenPerceptionStatus.value = status;
    if (!status.ready) {
      clearScreenObservation();
    }
  } catch (error: unknown) {
    if (
      !isRuntimeActive(runtimeEpoch) ||
      requestGeneration !== screenStatusRequestGeneration ||
      lifeIdentity.value?.id !== lifeId
    ) {
      return;
    }
    screenPerceptionStatus.value = undefined;
    clearScreenObservation();
    screenObservationError.value = screenObservationErrorFromUnknown(error);
  }
}

function applyCurrentLife(life: LifeIdentity, runtimeEpoch: number): void {
  if (!isRuntimeActive(runtimeEpoch)) {
    return;
  }
  const previousLifeId = lifeIdentity.value?.id;
  lifeIdentity.value = life;
  if (previousLifeId !== life.id) {
    screenStatusRequestGeneration += 1;
    screenPerceptionStatus.value = undefined;
    clearScreenObservation();
  }
  void refreshScreenPerceptionStatus(life.id, runtimeEpoch);
}

async function observeScreenNow(): Promise<void> {
  const lifeId = lifeIdentity.value?.id;
  if (lifeId === undefined || !canObserveScreen.value || screenObservationLoading.value) {
    return;
  }

  const runtimeEpoch = lifecycleEpoch;
  screenObservationLoading.value = true;
  screenObservationError.value = undefined;
  try {
    const observation = await mainScreenObservationService.observeNow(lifeId);
    if (
      isRuntimeActive(runtimeEpoch) &&
      lifeIdentity.value?.id === lifeId
    ) {
      screenObservation.value = observation;
    }
  } catch (error: unknown) {
    if (
      isRuntimeActive(runtimeEpoch) &&
      lifeIdentity.value?.id === lifeId
    ) {
      screenObservation.value = undefined;
      screenObservationError.value = screenObservationErrorFromUnknown(error);
    }
  } finally {
    if (
      isRuntimeActive(runtimeEpoch) &&
      lifeIdentity.value?.id === lifeId
    ) {
      screenObservationLoading.value = false;
      void refreshScreenPerceptionStatus(lifeId, runtimeEpoch);
    }
  }
}

function handleMainWindowFocus(): void {
  const lifeId = lifeIdentity.value?.id;
  if (lifeId !== undefined) {
    void refreshScreenPerceptionStatus(lifeId, lifecycleEpoch);
  }
}

onMounted(async () => {
  const runtimeEpoch = ++lifecycleEpoch;
  window.addEventListener("focus", handleMainWindowFocus);

  // Capture the mounted host before any asynchronous storage / Life work.
  // The captured element is used only after the same lifecycle epoch is
  // still active, so a late Life continuation cannot reuse a stale host.
  const hostElement = bodyRendererElement.value;

  const runtimeBinding = new BodyRuntimeBindingController({
    loadRegistrySnapshot: () => bodyPackageService.getRegistrySnapshot(),
    installRegistrySnapshot: installManagedBodyPackageRegistrySnapshot,
    loadCurrentLife: () => storageService.getCurrentLife(),
    // App owns only the opaque bodyId composition entrypoint. Package
    // definitions and managed source values stay inside the body authority.
    createPresentation: (bodyId) => createBodyPresentationForBodyId(bodyId),
    getCurrentState: () => bodyStateMachine.getState(),
    onSnapshot: (snapshot) => {
      if (isRuntimeActive(runtimeEpoch)) {
        bodyState.value = snapshot.state;
      }
    },
  });
  bodyRuntimeBinding = runtimeBinding;

  // D17-C-F1 ordering is retained: the BodyStateMachine subscription is
  // installed before the expression listener and before any initial render.
  // Before the current Life is bound, transitions remain authoritative in the
  // machine and are intentionally presentation no-ops.
  unsubscribe = bodyStateMachine.subscribe(({ current }) => {
    if (!isRuntimeActive(runtimeEpoch)) {
      return;
    }
    void runtimeBinding.render(current);
  });

  // Expression-listener registration starts BEFORE the long main
  // initialization sequence (storage, Life, persona, provider), so chat
  // expressions are not needlessly lost during startup.
  bodyExpressionListener.start(({ state }) => {
    bodyStateMachine.transition(state);
  });

  // This event is only a post-commit refresh hint. Main rereads the
  // authoritative registry and Life and never accepts a bodyId or URL from
  // the event payload.
  bodyBindingChangedListener.start((event) => {
    if (!isRuntimeActive(runtimeEpoch) || event.version !== 1) {
      return;
    }
    void runtimeBinding
      .refresh()
      .then((life) => {
        if (isRuntimeActive(runtimeEpoch) && life !== undefined) {
          applyCurrentLife(life, runtimeEpoch);
        }
      })
      .catch(() => {
        // Refresh failure is presentation-only; a later hint retries.
      });
  });

  await storageService.initialize();
  if (!isRuntimeActive(runtimeEpoch)) {
    return;
  }

  const life = await runtimeBinding.initialize(hostElement, () =>
    initializeDefaultLife(),
  );
  if (!isRuntimeActive(runtimeEpoch)) {
    return;
  }
  if (life === undefined) {
    return;
  }
  applyCurrentLife(life, runtimeEpoch);

  const persona = await personaManager.getById(life.personaId);
  if (isRuntimeActive(runtimeEpoch) && bodyRuntimeBinding === runtimeBinding) {
    personaTemplate.value = persona;
  }
});

function isRuntimeActive(epoch: number): boolean {
  return lifecycleEpoch === epoch;
}

onUnmounted(() => {
  // Retire the epoch before touching any async owner so late provider, Life,
  // mount, and render continuations cannot apply or create new presentation
  // state after unmount.
  lifecycleEpoch += 1;
  screenStatusRequestGeneration += 1;
  window.removeEventListener("focus", handleMainWindowFocus);
  unsubscribe?.();
  unsubscribe = undefined;
  bodyExpressionListener.stop();
  bodyBindingChangedListener.stop();
  bodyRuntimeBinding?.dispose();
  bodyRuntimeBinding = undefined;
});
</script>

<template>
  <main class="desktop-body">
    <section class="body-card" aria-label="Digital Life desktop body">
      <div class="window-actions">
        <button
          type="button"
          aria-label="Open chat"
          title="Chat"
          @mousedown.stop
          @click.stop="openChat"
        >
          Chat
        </button>
        <button
          type="button"
          aria-label="Open storage settings"
          title="Settings"
          @mousedown.stop
          @click.stop="openSettings"
        >
          ⚙
        </button>
      </div>
      <div
        ref="bodyRendererElement"
        class="body-renderer-host"
        aria-label="Digital Life desktop body"
      />
      <div class="status" data-tauri-drag-region>
        <strong>{{ lifeIdentity?.name }}</strong>
        <span>Life ID: {{ lifeIdentity?.id }}</span>
        <span>Persona: {{ personaTemplate?.name }}</span>
        <span>Persona Version: {{ personaTemplate?.version }}</span>
        <span>State: {{ bodyState }}</span>
        <span v-if="settingsError" class="settings-error">{{ settingsError }}</span>
      </div>
      <section
        class="screen-perception"
        aria-label="Screen perception"
        data-testid="main-screen-perception"
      >
        <div class="screen-perception-header">
          <strong data-testid="screen-perception-indicator">
            Screen perception: {{ screenReadinessLabel }}
          </strong>
          <button
            type="button"
            data-testid="screen-observe-now"
            :disabled="!canObserveScreen"
            :aria-busy="screenObservationLoading"
            @click="observeScreenNow"
          >
            {{ screenObservationLoading ? "Observing…" : "Observe Now" }}
          </button>
        </div>
        <pre
          v-if="screenObservation"
          class="screen-observation-preview"
          data-testid="screen-observation-preview"
          aria-live="polite"
        >{{ screenObservation.text }}</pre>
        <p
          v-if="screenObservationError"
          class="screen-perception-error"
          data-testid="screen-observation-error"
        >
          {{ screenObservationError.message }}
        </p>
      </section>
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

.window-actions {
  position: absolute;
  z-index: 1;
  top: 0.25rem;
  right: 0.25rem;
  display: flex;
  gap: 0.35rem;
}

.window-actions button {
  min-width: 2rem;
  height: 2rem;
  border: 1px solid rgb(255 255 255 / 32%);
  border-radius: 999px;
  background: rgb(15 23 42 / 82%);
  color: #e0f2fe;
  cursor: pointer;
  font-size: 1rem;
  line-height: 1;
}

.window-actions button:hover,
.window-actions button:focus-visible {
  background: rgb(14 116 144 / 92%);
}

.body-image {
  width: min(72vw, 300px);
  max-height: 470px;
  object-fit: contain;
  -webkit-user-drag: none;
}

.body-renderer-host {
  width: min(72vw, 300px);
  height: min(64vh, 420px);
  min-width: 1px;
  min-height: 1px;
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

.screen-perception {
  display: grid;
  width: min(100%, 320px);
  gap: 0.4rem;
  padding: 0.6rem;
  border: 1px solid rgb(255 255 255 / 18%);
  border-radius: 0.7rem;
  background: rgb(15 23 42 / 66%);
  user-select: text;
}

.screen-perception-header {
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 0.5rem;
  align-items: center;
}

.screen-perception-header strong {
  color: #d9faff;
  font-size: 0.82rem;
  font-weight: 600;
}

.screen-perception-header button {
  border: 1px solid rgb(125 211 252 / 45%);
  border-radius: 0.45rem;
  padding: 0.3rem 0.55rem;
  background: rgb(14 116 144 / 80%);
  color: #f0fdfa;
  cursor: pointer;
  font-size: 0.78rem;
}

.screen-perception-header button:disabled {
  background: rgb(71 85 105 / 65%);
  color: #cbd5e1;
  cursor: not-allowed;
}

.screen-perception-header button:not(:disabled):hover,
.screen-perception-header button:not(:disabled):focus-visible {
  background: rgb(8 145 178 / 90%);
}

.screen-observation-preview {
  max-height: 8rem;
  margin: 0;
  overflow: auto;
  border-radius: 0.4rem;
  padding: 0.45rem;
  background: rgb(2 6 23 / 72%);
  color: #e2e8f0;
  font: 0.75rem/1.35 ui-monospace, SFMono-Regular, Consolas, monospace;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.screen-perception-error {
  margin: 0;
  color: #fecaca;
  font-size: 0.78rem;
}

</style>
