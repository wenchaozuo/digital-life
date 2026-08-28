<script setup lang="ts">
import { invoke } from "@tauri-apps/api/core";
import { onMounted, onUnmounted, ref } from "vue";
import {
  BodyExpressionListenerLifecycle,
  BodyRendererHost,
  PngBodyRenderer,
  bodyExpressionBridge,
  bodyRenderCoordinator,
  bodyStateMachine,
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
let bodyRendererHost: BodyRendererHost | undefined;

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
  // D18-B1: the main renderer host is mounted FIRST (synchronous invocation
  // of the async lifecycle) so no BodySnapshot can ever be rendered before
  // the renderer exists.  The main WebView is the only production owner of
  // the renderer instance.  Mount failure is presentation-only: it is
  // contained here and never blocks storage / Life / persona
  // initialization, Conversation, BodyStateMachine authority, or SQLite.
  const hostElement = bodyRendererElement.value;
  if (hostElement !== undefined) {
    bodyRendererHost = new BodyRendererHost(new PngBodyRenderer());
    const rendererMount = bodyRendererHost.mount(hostElement);
    void rendererMount.catch(() => {
      // Contained: the host rolls back to unmounted and the renderer path
      // reports bounded errors on later render attempts.
    });
  }

  // D17-C-F1 ordering: the BodyStateMachine -> BodyRenderCoordinator
  // subscription is installed FIRST, before the expression listener and
  // before the initial async render can be pending.  There is therefore no
  // interval in which an expression can transition BodyStateMachine while a
  // body render is pending but the machine has no renderer subscriber: every
  // mounted transition creates a render request and advances the render
  // generation, so a late old initial completion can never overwrite a newer
  // expression state.
  unsubscribe = bodyStateMachine.subscribe(({ current }) => {
    void bodyRenderCoordinator
      .render(current)
      .then((result) => {
        if (result.applied) {
          applyBodySnapshot(result.snapshot);
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

  // The initial render goes through the same fenced provider/fallback path
  // as every later transition; there is no unfenced special load path.  The
  // renderer subscription above guarantees a transition arriving while this
  // render is pending requests its own generation-fenced render.
  try {
    const initial = await bodyRenderCoordinator.render(bodyStateMachine.getState());
    if (initial.applied) {
      applyBodySnapshot(initial.snapshot);
    }
  } catch {
    // Presentation-only failure: keep the initial refs untouched.
  }

  await storageService.initialize();
  lifeIdentity.value = await initializeDefaultLife();
  personaTemplate.value = await personaManager.getById(lifeIdentity.value.personaId);
});

function applyBodySnapshot(snapshot: BodySnapshot): void {
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
  unsubscribe?.();
  bodyRendererHost?.dispose();
  bodyRendererHost = undefined;
  bodyExpressionListener.stop();
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
