<script setup lang="ts">
import { onMounted, onUnmounted, ref } from "vue";
import { bodyStateMachine, defaultBodyProvider, type BodyState } from "./body";
import { initializeDefaultLife, type LifeIdentity } from "./life";
import { personaManager, type PersonaTemplate } from "./persona";
import { storageService } from "./storage";

const bodyState = ref<BodyState>("idle");
const bodyResource = ref("");
const lifeIdentity = ref<LifeIdentity>();
const personaTemplate = ref<PersonaTemplate>();
let unsubscribe: (() => void) | undefined;

onMounted(async () => {
  await storageService.initialize();
  lifeIdentity.value = await initializeDefaultLife();
  personaTemplate.value = await personaManager.getById(lifeIdentity.value.personaId);

  const body = await defaultBodyProvider.load(bodyStateMachine.getState());
  bodyState.value = body.state;
  bodyResource.value = body.resourcePath;

  unsubscribe = bodyStateMachine.subscribe(async ({ current }) => {
    const nextBody = await defaultBodyProvider.switchState(current);
    bodyState.value = nextBody.state;
    bodyResource.value = nextBody.resourcePath;
  });
});

onUnmounted(() => unsubscribe?.());
</script>

<template>
  <main class="desktop-body" data-tauri-drag-region>
    <section class="body-card" aria-label="Digital Life desktop body">
      <img
        v-if="bodyResource"
        :src="bodyResource"
        :alt="`Digital Life ${bodyState} body`"
        class="body-image"
        draggable="false"
      />
      <div class="status" data-tauri-drag-region>
        <strong>{{ lifeIdentity?.name }}</strong>
        <span>Life ID: {{ lifeIdentity?.id }}</span>
        <span>Persona: {{ personaTemplate?.name }}</span>
        <span>Persona Version: {{ personaTemplate?.version }}</span>
        <span>State: {{ bodyState }}</span>
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
  display: grid;
  justify-items: center;
  gap: 0.5rem;
  max-width: min(82vw, 340px);
  padding: 1rem;
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
</style>
