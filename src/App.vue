<script setup lang="ts">
import { invoke } from "@tauri-apps/api/core";
import { onMounted, onUnmounted, ref } from "vue";
import {
  BodyExpressionListenerLifecycle,
  BodyRendererHost,
  bodyExpressionBridge,
  bodyStateMachine,
  BodyRenderCoordinator,
  createBodyPresentationForBodyId,
  type BodySnapshot,
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
let activeBodyRenderCoordinator: BodyRenderCoordinator | undefined;
let bodyRendererHost: BodyRendererHost | undefined;
let lifecycleEpoch = 0;

// D17-C: the listener registration race with unmount is fenced by this
// controller, so a registration promise resolving after unmount is
// immediately unlistened.
const bodyExpressionListener = new BodyExpressionListenerLifecycle((handler) =>
  bodyExpressionBridge.listenForBodyExpression(handler),
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

  // D17-C-F1 ordering is retained: the BodyStateMachine subscription is
  // installed before the expression listener and before any initial render.
  // Before the current Life is bound, transitions remain authoritative in the
  // machine and are intentionally presentation-no-ops.
  unsubscribe = bodyStateMachine.subscribe(({ current }) => {
    const coordinator = activeBodyRenderCoordinator;
    if (!isRuntimeActive(runtimeEpoch) || coordinator === undefined) {
      return;
    }

    void coordinator
      .render(current)
      .then((result) => {
        if (result.applied) {
          applyBodySnapshot(result.snapshot, runtimeEpoch, coordinator);
        }
      })
      .catch(() => {
        // Presentation-only failure: keep the last applied body.
      });
  });

  // Expression-listener registration starts BEFORE the long main
  // initialization sequence (storage, Life, persona, provider), so chat
  // expressions are not needlessly lost during startup.
  bodyExpressionListener.start(({ state }) => {
    bodyStateMachine.transition(state);
  });

  await storageService.initialize();
  if (!isRuntimeActive(runtimeEpoch)) {
    return;
  }

  const life = await initializeDefaultLife();
  if (!isRuntimeActive(runtimeEpoch)) {
    return;
  }
  lifeIdentity.value = life;

  // Life.bodyId is the authoritative startup selector.  The canonical
  // factory returns one matched provider/renderer composition; no default
  // body is created before this point and no selector is rewritten here.
  const composition = createBodyPresentationForBodyId(life.bodyId);
  const coordinator = new BodyRenderCoordinator(composition.provider);
  const host = new BodyRendererHost(composition.renderer);
  if (!isRuntimeActive(runtimeEpoch)) {
    host.dispose();
    return;
  }

  activeBodyRenderCoordinator = coordinator;
  bodyRendererHost = host;

  if (hostElement !== undefined) {
    // Mount failure is presentation-only and does not block the Life or
    // persona startup path.  BodyRendererHost owns the async lifecycle
    // fence and contains a late mount after this runtime is retired.
    const rendererMount = host.mount(hostElement);
    void rendererMount.catch(() => {
      // Contained: the host rolls back to unmounted and later render errors
      // remain bounded at the presentation boundary.
    });
  }

  // The first Life-bound render uses the current machine state, including an
  // expression captured while binding was still pending.  It shares the same
  // generation-fenced coordinator as every later transition.
  try {
    const initial = await coordinator.render(bodyStateMachine.getState());
    if (!isRuntimeActive(runtimeEpoch) || activeBodyRenderCoordinator !== coordinator) {
      return;
    }
    if (initial.applied) {
      applyBodySnapshot(initial.snapshot, runtimeEpoch, coordinator);
    }

    if (!isRuntimeActive(runtimeEpoch) || activeBodyRenderCoordinator !== coordinator) {
      return;
    }
  } catch {
    // Presentation-only failure: keep the last applied body and continue
    // Life/persona startup without inventing a snapshot.
  }

  if (!isRuntimeActive(runtimeEpoch) || activeBodyRenderCoordinator !== coordinator) {
    return;
  }

  const persona = await personaManager.getById(life.personaId);
  if (isRuntimeActive(runtimeEpoch) && activeBodyRenderCoordinator === coordinator) {
    personaTemplate.value = persona;
  }
});

function isRuntimeActive(epoch: number): boolean {
  return lifecycleEpoch === epoch;
}

function applyBodySnapshot(
  snapshot: BodySnapshot,
  runtimeEpoch: number,
  coordinator: BodyRenderCoordinator,
): void {
  if (!isRuntimeActive(runtimeEpoch) || activeBodyRenderCoordinator !== coordinator) {
    return;
  }
  bodyState.value = snapshot.state;
  const host = bodyRendererHost;
  if (host === undefined) {
    return;
  }
  // Renderer failure is presentation-only: it never affects Conversation,
  // BodyStateMachine authority, Life, or SQLite; the last successfully
  // rendered body stays visible.
  void host.render(snapshot).catch(() => {
    // Contained: keep the last rendered presentation.
  });
}

onUnmounted(() => {
  // Retire the epoch before touching any async owner so late provider, Life,
  // mount, and render continuations cannot apply or create new presentation
  // state after unmount.
  lifecycleEpoch += 1;
  unsubscribe?.();
  unsubscribe = undefined;
  bodyExpressionListener.stop();
  bodyRendererHost?.dispose();
  bodyRendererHost = undefined;
  activeBodyRenderCoordinator = undefined;
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
