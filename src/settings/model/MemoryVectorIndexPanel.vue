<script setup lang="ts">
import { onMounted, onUnmounted, reactive, ref } from "vue";
import {
  MemoryVectorIndexController,
  isRunningStatus,
} from "./memoryVectorIndexController.ts";
import type { VectorIndexJobStatus } from "./memoryVectorIndexService.ts";

const props = defineProps<{
  syncRunning?: boolean;
}>();

const controller = reactive(new MemoryVectorIndexController());
const activeEmbeddingProfileChanged = ref(false);

const stageLabels: Record<VectorIndexJobStatus, string> = {
  queued: "Waiting to start",
  resolvingProfile: "Resolving Embedding configuration",
  scanning: "Scanning memories",
  embedding: "Generating vectors",
  writing: "Writing the index",
  completed: "Rebuild completed",
  failed: "Rebuild failed",
  cancelled: "Cancelled",
};

function onVisibilityChange(): void {
  if (document.visibilityState === "hidden") {
    controller.deactivate();
    return;
  }
  void controller.activate();
}

function openRebuildConfirmation(): void {
  controller.requestRebuildConfirmation();
}

function confirmRebuild(): void {
  void controller.confirmRebuild();
}

function requestCancel(): void {
  if (!controller.canCancelJob) {
    return;
  }
  if (
    !window.confirm(
      "Cancel this rebuild? An active HTTP request may finish before cancellation takes effect. SQLite is not changed; if writing has begun, run a complete rebuild again if needed.",
    )
  ) {
    return;
  }
  void controller.requestCancel();
}

function stageLabel(status: VectorIndexJobStatus | undefined): string {
  return status ? stageLabels[status] : "No task";
}

function refreshStatus(): void {
  void controller.refreshStatus();
}

function notifyActiveEmbeddingProfileChanged(): void {
  activeEmbeddingProfileChanged.value = true;
  refreshStatus();
}

onMounted(() => {
  void controller.activate();
  document.addEventListener("visibilitychange", onVisibilityChange);
});

onUnmounted(() => {
  document.removeEventListener("visibilitychange", onVisibilityChange);
  controller.deactivate();
});

defineExpose({
  refreshStatus,
  notifyActiveEmbeddingProfileChanged,
  deactivate: controller.deactivate.bind(controller),
});
</script>

<template>
  <section class="memory-vector-index-panel" aria-label="Memory vector index">
    <header>
      <div>
        <h3>Memory vector index</h3>
        <p>Derived LanceDB index for confirmed, non-sensitive long-term memories.</p>
      </div>
      <button type="button" :disabled="controller.state === 'loadingStatus'" @click="refreshStatus">
        Refresh status
      </button>
    </header>

    <section v-if="controller.state === 'loadingStatus' && !controller.status" class="index-note">
      Loading index status…
    </section>

    <section v-else-if="!controller.lifeId" class="index-note error" role="alert">
      A current life identity is required before memory indexing can be managed.
    </section>

    <template v-else-if="controller.status">
      <dl class="index-summary">
        <div><dt>Active Embedding profile</dt><dd>{{ controller.status.activeEmbeddingProfileExists ? "Available" : "Not configured" }}</dd></div>
        <div><dt>Credential</dt><dd>{{ controller.status.credentialExists ? "Saved" : "Not saved" }}</dd></div>
        <div><dt>Embedding model</dt><dd>{{ controller.status.embeddingModel ?? "Not available" }}</dd></div>
        <div><dt>Configured dimension</dt><dd>{{ controller.status.configuredDimension ?? "Not available" }}</dd></div>
        <div><dt>Index directory</dt><dd>{{ controller.status.indexDirectoryExists ? "Established" : "Not established" }}</dd></div>
        <div><dt>Eligible memories</dt><dd>{{ controller.status.eligibleMemoryCount }}</dd></div>
        <div><dt>Current indexed memories</dt><dd>{{ controller.status.indexedCount }}</dd></div>
        <div><dt>Latest task</dt><dd>{{ stageLabel(controller.job?.status ?? controller.status.lastJob?.status) }}</dd></div>
      </dl>

      <section class="index-note" :class="controller.status.rebuildRecommended ? 'recommended' : ''">
        <strong>{{ controller.status.rebuildRecommended ? "Rebuild recommended" : "Current status is for guidance only" }}</strong>
        <p>{{ controller.status.reason ?? "Index count and eligible-memory count may match, but that does not prove indexed content is current." }}</p>
      </section>

      <section v-if="activeEmbeddingProfileChanged" class="index-note recommended">
        <strong>Active Embedding model changed</strong>
        <p>The current active Embedding model has changed. Manually rebuild the index when ready.</p>
      </section>

      <section v-if="controller.job" class="job-progress" :aria-label="`Index task ${controller.job.status}`">
        <strong>{{ stageLabel(controller.job.status) }}</strong>
        <dl>
          <div><dt>Scanned</dt><dd>{{ controller.job.progress.scannedCount }}</dd></div>
          <div><dt>Eligible</dt><dd>{{ controller.job.progress.eligibleCount }}</dd></div>
          <div><dt>Embedded</dt><dd>{{ controller.job.progress.embeddedCount }}</dd></div>
          <div><dt>Indexed</dt><dd>{{ controller.job.progress.indexedCount }}</dd></div>
          <div><dt>Skipped candidate</dt><dd>{{ controller.job.progress.skippedCandidateCount }}</dd></div>
          <div><dt>Skipped sensitive</dt><dd>{{ controller.job.progress.skippedSensitiveCount }}</dd></div>
          <div v-if="controller.job.progress.totalBatches > 0"><dt>Batch</dt><dd>{{ controller.job.progress.currentBatch }} / {{ controller.job.progress.totalBatches }}</dd></div>
          <div v-if="controller.job.progress.embeddingModel"><dt>Task model</dt><dd>{{ controller.job.progress.embeddingModel }}</dd></div>
          <div v-if="controller.job.progress.dimension"><dt>Task dimension</dt><dd>{{ controller.job.progress.dimension }}</dd></div>
        </dl>
      </section>

      <section v-if="controller.state === 'confirmingRebuild'" class="confirmation" aria-label="Rebuild index confirmation">
        <h4>Rebuild memory vector index?</h4>
        <ul>
          <li>This will call the configured Embedding service and may incur API charges.</li>
          <li>Only confirmed, non-sensitive memories are processed. Candidate and sensitive memories are not sent.</li>
          <li>SQLite memories are not deleted or modified. LanceDB is a rebuildable derived index.</li>
        </ul>
        <div class="actions">
          <button type="button" @click="controller.cancelRebuildConfirmation">Back</button>
          <button type="button" class="primary" @click="confirmRebuild">Confirm rebuild</button>
        </div>
      </section>

      <div class="actions">
        <button type="button" class="primary" :disabled="!controller.canStartRebuild || props.syncRunning" @click="openRebuildConfirmation">
          Rebuild index
        </button>
        <button
          v-if="controller.job && isRunningStatus(controller.job.status)"
          type="button"
          class="danger"
          :disabled="!controller.canCancelJob"
          @click="requestCancel"
        >
          {{ controller.cancelRequested ? "Cancelling…" : "Cancel task" }}
        </button>
      </div>
    </template>

    <section v-if="controller.error" class="index-error" role="alert">
      <strong>{{ controller.error.code }}</strong>
      <p>{{ controller.error.message }}</p>
      <p>Operation: {{ controller.error.operation }}</p>
    </section>
  </section>
</template>

<style scoped>
.memory-vector-index-panel { display: grid; gap: 0.8rem; border: 1px solid #475569; border-radius: 0.7rem; background: #111827; padding: 1rem; }
header, .actions { display: flex; gap: 0.6rem; align-items: start; justify-content: space-between; }
h3, h4, p { margin: 0; }
header p, dt { color: #94a3b8; font-size: 0.85rem; }
.index-summary, .job-progress dl { display: grid; gap: 0.35rem; margin: 0; }
.index-summary div, .job-progress dl div { display: grid; grid-template-columns: minmax(10rem, 1fr) minmax(0, 1fr); gap: 0.6rem; }
dd { margin: 0; overflow-wrap: anywhere; color: #bae6fd; }
.index-note, .job-progress, .confirmation, .index-error { display: grid; gap: 0.5rem; border: 1px solid #334155; border-radius: 0.55rem; padding: 0.75rem; }
.recommended { border-color: #f59e0b; }
.confirmation { border-color: #f59e0b; }
.confirmation ul { display: grid; gap: 0.35rem; margin: 0; padding-left: 1.25rem; }
.primary { border-color: #0284c7; background: #0369a1; }
.danger { border-color: #dc2626; background: #991b1b; }
.error, .index-error { border-color: #dc2626; color: #fecaca; }
@media (max-width: 620px) { header, .actions { align-items: stretch; flex-direction: column; } .index-summary div, .job-progress dl div { grid-template-columns: 1fr; } }
</style>
