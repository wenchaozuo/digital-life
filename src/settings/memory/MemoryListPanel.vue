<script setup lang="ts">
import type { MemoryCenterController } from "./memoryCenterController.ts";
import type { MemoryKind, MemoryStatus } from "./types.ts";

const props = defineProps<{ controller: MemoryCenterController }>();

const statusOptions: Array<{ value: MemoryStatus | "all"; label: string }> = [
  { value: "all", label: "All statuses" },
  { value: "confirmed", label: "Confirmed" },
  { value: "candidate", label: "Candidate" },
];

const kindOptions: Array<{ value: MemoryKind | "all"; label: string }> = [
  { value: "all", label: "All kinds" },
  { value: "experience", label: "Experience" },
  { value: "preference", label: "Preference" },
  { value: "fact", label: "Fact" },
  { value: "relationship", label: "Relationship" },
  { value: "goal", label: "Goal" },
  { value: "skill", label: "Skill" },
  { value: "other", label: "Other" },
];

function onStatusChange(event: Event): void {
  const value = (event.target as HTMLSelectElement).value as MemoryStatus | "all";
  props.controller.updateFilters({ status: value });
}

function onKindChange(event: Event): void {
  const value = (event.target as HTMLSelectElement).value as MemoryKind | "all";
  props.controller.updateFilters({ kind: value });
}

function onSensitiveChange(event: Event): void {
  const value = (event.target as HTMLSelectElement).value;
  props.controller.updateFilters({
    sensitive: value === "all" ? undefined : value === "true",
  });
}

function onQueryInput(event: Event): void {
  const value = (event.target as HTMLInputElement).value;
  props.controller.filters.query = value;
}

function onQueryKeydown(event: KeyboardEvent): void {
  if (event.key === "Enter") {
    props.controller.updateFilters({ query: props.controller.filters.query });
  }
}

function applyQuery(): void {
  props.controller.updateFilters({ query: props.controller.filters.query });
}

function formatTimestamp(ts: string): string {
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

function kindBadgeClass(kind: string): string {
  return `kind-badge kind-${kind}`;
}
</script>

<template>
  <section class="memory-list-panel" aria-label="Memory list">
    <!-- Filters -->
    <div class="filters">
      <div class="filter-row">
        <select
          :value="controller.filters.status"
          aria-label="Filter by status"
          @change="onStatusChange"
        >
          <option v-for="opt in statusOptions" :key="opt.value" :value="opt.value">
            {{ opt.label }}
          </option>
        </select>

        <select
          :value="controller.filters.kind"
          aria-label="Filter by kind"
          @change="onKindChange"
        >
          <option v-for="opt in kindOptions" :key="opt.value" :value="opt.value">
            {{ opt.label }}
          </option>
        </select>

        <select
          :value="controller.filters.sensitive === undefined ? 'all' : String(controller.filters.sensitive)"
          aria-label="Filter by sensitive"
          @change="onSensitiveChange"
        >
          <option value="all">All sensitivity</option>
          <option value="true">Sensitive</option>
          <option value="false">Not sensitive</option>
        </select>
      </div>

      <div class="search-row">
        <input
          type="text"
          :value="controller.filters.query"
          placeholder="Search memory content…"
          aria-label="Search memories"
          @input="onQueryInput"
          @keydown="onQueryKeydown"
        />
        <button type="button" @click="applyQuery">Search</button>
      </div>
    </div>

    <!-- List state -->
    <div v-if="controller.listPhase === 'loading'" class="empty-state">
      Loading memories…
    </div>

    <div v-else-if="controller.listPhase === 'failed'" class="empty-state error" role="alert">
      <strong>{{ controller.listError?.code }}</strong>
      <p>{{ controller.listError?.message }}</p>
      <button type="button" @click="controller.refreshList()">Retry</button>
    </div>

    <div v-else-if="controller.memories.length === 0" class="empty-state">
      <strong>No memories found.</strong>
      <p>Try adjusting your filters or search query.</p>
    </div>

    <!-- Memory list -->
    <div v-else class="memory-items">
      <button
        v-for="memory in controller.memories"
        :key="memory.id"
        type="button"
        class="memory-item"
        :class="{ selected: controller.selectedMemoryId === memory.id }"
        @click="controller.selectMemory(memory.id)"
      >
        <div class="memory-item-header">
          <span :class="kindBadgeClass(memory.kind)">{{ memory.kind }}</span>
          <span class="status-badge" :class="`status-${memory.status}`">
            {{ memory.status }}
          </span>
          <span v-if="memory.isSensitive" class="sensitive-badge">sensitive</span>
          <span class="revision-label">rev {{ memory.revision }}</span>
        </div>
        <p class="memory-summary">
          {{ memory.summary ?? "(no summary)" }}
        </p>
        <time class="memory-time" :datetime="memory.updatedAt">
          {{ formatTimestamp(memory.updatedAt) }}
        </time>
      </button>

      <!-- Load more -->
      <div v-if="controller.hasMore" class="load-more">
        <button
          type="button"
          :disabled="controller.isLoadingMore"
          @click="controller.loadMore()"
        >
          {{ controller.isLoadingMore ? "Loading…" : "Load more" }}
        </button>
      </div>
    </div>
  </section>
</template>

<style scoped>
.memory-list-panel {
  display: grid;
  gap: 0.75rem;
}

.filters {
  display: grid;
  gap: 0.5rem;
}

.filter-row {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.filter-row select,
.search-row input {
  min-width: 0;
  flex: 1;
  border: 1px solid #475569;
  border-radius: 0.45rem;
  background: #0f172a;
  color: #f8fafc;
  padding: 0.45rem 0.6rem;
  font: inherit;
}

.search-row {
  display: flex;
  gap: 0.5rem;
}

.search-row input {
  flex: 1;
}

.empty-state {
  display: grid;
  gap: 0.5rem;
  border: 1px dashed #475569;
  border-radius: 0.7rem;
  color: #cbd5e1;
  padding: 1rem;
}

.error {
  border-color: #dc2626;
  color: #fecaca;
}

.memory-items {
  display: grid;
  gap: 0.5rem;
}

.memory-item {
  display: grid;
  gap: 0.35rem;
  text-align: left;
  border: 1px solid #334155;
  border-radius: 0.6rem;
  padding: 0.7rem;
  background: #172033;
  transition: border-color 0.15s;
}

.memory-item:hover:not(.selected) {
  border-color: #475569;
}

.memory-item.selected {
  border-color: #38bdf8;
  background: #0c2d48;
}

.memory-item-header {
  display: flex;
  gap: 0.4rem;
  align-items: center;
  flex-wrap: wrap;
}

.kind-badge {
  font-size: 0.75rem;
  font-weight: 600;
  padding: 0.15rem 0.45rem;
  border-radius: 0.3rem;
  background: #1e293b;
  color: #94a3b8;
  border: 1px solid #475569;
}

.kind-experience { color: #38bdf8; border-color: #0369a1; }
.kind-preference { color: #a78bfa; border-color: #6d28d9; }
.kind-fact { color: #34d399; border-color: #059669; }
.kind-relationship { color: #fb7185; border-color: #be123c; }
.kind-goal { color: #fbbf24; border-color: #b45309; }
.kind-skill { color: #2dd4bf; border-color: #0d9488; }
.kind-other { color: #94a3b8; border-color: #475569; }

.status-badge {
  font-size: 0.7rem;
  font-weight: 600;
  padding: 0.1rem 0.35rem;
  border-radius: 0.25rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.status-confirmed {
  background: #064e3b;
  color: #6ee7b7;
}

.status-candidate {
  background: #78350f;
  color: #fcd34d;
}

.sensitive-badge {
  font-size: 0.7rem;
  font-weight: 600;
  padding: 0.1rem 0.35rem;
  border-radius: 0.25rem;
  background: #7f1d1d;
  color: #fca5a5;
}

.revision-label {
  font-size: 0.7rem;
  color: #64748b;
  margin-left: auto;
}

.memory-summary {
  margin: 0;
  font-size: 0.85rem;
  color: #e2e8f0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.memory-time {
  font-size: 0.75rem;
  color: #64748b;
}

.load-more {
  display: flex;
  justify-content: center;
  padding: 0.5rem 0;
}

@media (max-width: 860px) {
  .filter-row {
    flex-direction: column;
  }
}
</style>
