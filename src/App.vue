<script setup lang="ts">
import { invoke } from "@tauri-apps/api/core";
import { onMounted, onUnmounted, ref } from "vue";
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
import { storageService } from "./storage";

const bodyState = ref<BodyState>("idle");
const bodyRendererElement = ref<HTMLElement>();
const lifeIdentity = ref<LifeIdentity>();
const personaTemplate = ref<PersonaTemplate>();
const settingsError = ref("");
let unsubscribe: (() => void) | undefined;
let bodyRuntimeBinding: BodyRuntimeBindingController | undefined;
let lifecycleEpoch = 0;

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

onMounted(async () => {
  const runtimeEpoch = ++lifecycleEpoch;

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
          lifeIdentity.value = life;
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
  lifeIdentity.value = life;

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

</style>
