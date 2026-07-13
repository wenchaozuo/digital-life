<script setup lang="ts">
import { onMounted, onUnmounted, reactive } from "vue";
import { MemoryCenterController } from "./memoryCenterController.ts";
import MemoryListPanel from "./MemoryListPanel.vue";
import MemoryDetailPanel from "./MemoryDetailPanel.vue";

const controller = reactive(new MemoryCenterController());

function requestLeave(): boolean {
  if (controller.editDraft !== null) {
    if (!window.confirm("Discard unsaved memory changes?")) {
      return false;
    }
    controller.closeEditForm();
  }
  if (controller.deleteConfirmVisible) {
    controller.closeDeleteConfirm();
  }
  return true;
}

function clearSensitiveInputs(): void {
  // No sensitive inputs in memory center
}

function onVisibilityChange(): void {
  if (document.visibilityState === "hidden") {
    clearSensitiveInputs();
  }
}

onMounted(() => {
  void controller.refreshList();
  document.addEventListener("visibilitychange", onVisibilityChange);
});

onUnmounted(() => {
  document.removeEventListener("visibilitychange", onVisibilityChange);
});

defineExpose({ clearSensitiveInputs, requestLeave });
</script>

<template>
  <section class="memory-center-view" aria-label="Memory center">
    <header class="memory-header">
      <div>
        <h2>Memory Center</h2>
        <p>View, search, and manage all long-term memories.</p>
      </div>
    </header>

    <div class="memory-layout">
      <MemoryListPanel
        :controller="controller"
        class="memory-list-section"
      />
      <MemoryDetailPanel
        :controller="controller"
        class="memory-detail-section"
      />
    </div>
  </section>
</template>

<style scoped>
.memory-center-view {
  display: grid;
  gap: 1rem;
}

.memory-header {
  display: flex;
  gap: 1rem;
  align-items: start;
  justify-content: space-between;
}

.memory-header h2,
.memory-header p {
  margin: 0;
}

.memory-header p {
  color: #cbd5e1;
}

.memory-layout {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
  align-items: start;
}

.memory-list-section {
  min-height: 0;
}

.memory-detail-section {
  min-height: 0;
}

@media (max-width: 860px) {
  .memory-layout {
    grid-template-columns: 1fr;
  }
}
</style>
