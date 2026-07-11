<script setup lang="ts">
import { storeToRefs } from "pinia";
import { useAppStore } from "./stores/app";

const { appReady, currentVersion } = storeToRefs(useAppStore());
</script>

<template>
  <main>
    <h1>Digital Life</h1>
    <p>{{ currentVersion }} 基础生命体</p>
    <p>{{ appReady ? "Application initialized successfully" : "Application is initializing" }}</p>
  </main>
</template>

<style>
:root {
  font-family: Inter, ui-sans-serif, system-ui, sans-serif;
  color: #1f2937;
  background: #f8fafc;
}

body {
  margin: 0;
  min-width: 320px;
}

main {
  display: grid;
  min-height: 100vh;
  place-content: center;
  gap: 0.5rem;
  text-align: center;
}

h1,
p {
  margin: 0;
}
</style>
