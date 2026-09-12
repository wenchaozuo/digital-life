<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import {
  CAPABILITY_ACTIVATION_CODES,
  activationErrorCode,
  activationErrorText,
  capabilityDescription,
  capabilityActivationService,
  requiresCriticalAcknowledgement,
  type CapabilityAuthorizationEntryView,
  type CapabilityAuthorizationSnapshot,
} from "./capabilityActivationService";

const snapshot = ref<CapabilityAuthorizationSnapshot>();
const loading = ref(true);
const busy = ref(false);
const error = ref<string>();
const notice = ref<string>();
/** Second-step confirmation target. Enabling is never a one-click toggle. */
const pendingEnable = ref<{
  entry: CapabilityAuthorizationEntryView;
  observedLifeId: string;
}>();
const pendingEnableAcknowledged = ref(false);
let refreshGeneration = 0;

const capabilities = computed(() => snapshot.value?.capabilities ?? []);
const pendingEnableEntry = computed(() => pendingEnable.value?.entry);
const lifeUnavailable = computed(
  () => error.value !== undefined && error.value.includes("No current Life"),
);

async function refresh(): Promise<void> {
  const generation = ++refreshGeneration;
  // A refresh invalidates both the old cards and any confirmation derived from
  // them. No failed refresh may leave an actionable stale Life on screen.
  cancelEnable();
  snapshot.value = undefined;
  loading.value = true;
  error.value = undefined;
  try {
    const nextSnapshot = await capabilityActivationService.getSnapshot();
    if (generation !== refreshGeneration) return;
    snapshot.value = nextSnapshot;
  } catch (caught) {
    if (generation !== refreshGeneration) return;
    snapshot.value = undefined;
    error.value = activationErrorText(
      caught,
      "Capability permissions are unavailable.",
    );
  } finally {
    if (generation === refreshGeneration) loading.value = false;
  }
}

function requestEnable(entry: CapabilityAuthorizationEntryView): void {
  const observedLifeId = snapshot.value?.lifeId;
  if (!observedLifeId) return;
  pendingEnable.value = { entry, observedLifeId };
  pendingEnableAcknowledged.value = false;
  notice.value = undefined;
}

function cancelEnable(): void {
  pendingEnable.value = undefined;
  pendingEnableAcknowledged.value = false;
}

async function applyTransition(
  entry: CapabilityAuthorizationEntryView,
  enabled: boolean,
  observedLifeId: string,
): Promise<void> {
  if (busy.value) return;
  busy.value = true;
  error.value = undefined;
  notice.value = undefined;
  try {
    const result = await capabilityActivationService.setEnabled(
      entry.capabilityId,
      enabled,
      entry.revision,
      observedLifeId,
    );
    notice.value = result.enabled
      ? `Enabled ${entry.displayName}. Each use still requires your explicit confirmation.`
      : `Disabled ${entry.displayName}.`;
    cancelEnable();
    await refresh();
  } catch (caught) {
    const code = activationErrorCode(caught);
    if (code === CAPABILITY_ACTIVATION_CODES.lifeChanged) {
      cancelEnable();
      await refresh();
      notice.value = "Current Life changed. Review permissions again.";
    } else if (code === CAPABILITY_ACTIVATION_CODES.revisionConflict) {
      // Stale local state: refresh and ask the user to decide again. A
      // revision conflict is never silently converted into success and the
      // requested change is never retried automatically.
      cancelEnable();
      await refresh();
      notice.value =
        "Capability permissions changed elsewhere. The list was refreshed; review the current state and try again.";
    } else if (code === CAPABILITY_ACTIVATION_CODES.noTransition) {
      cancelEnable();
      await refresh();
      notice.value = "That capability was already in the requested state.";
    } else {
      error.value = activationErrorText(
        caught,
        "The capability permission change could not be applied.",
      );
    }
  } finally {
    busy.value = false;
  }
}

async function confirmEnable(): Promise<void> {
  const pending = pendingEnable.value;
  if (!pending || !pendingEnableAcknowledged.value) return;
  await applyTransition(pending.entry, true, pending.observedLifeId);
}

async function disableCapability(entry: CapabilityAuthorizationEntryView): Promise<void> {
  const observedLifeId = snapshot.value?.lifeId;
  if (!observedLifeId) return;
  await applyTransition(entry, false, observedLifeId);
}

function lastUpdated(entry: CapabilityAuthorizationEntryView): string {
  return new Date(entry.updatedAt).toLocaleString();
}

function eventTime(changedAt: string): string {
  return new Date(changedAt).toLocaleString();
}

function transitionLabel(event: { oldEnabled: boolean; newEnabled: boolean }): string {
  if (!event.oldEnabled && event.newEnabled) return "Enabled";
  if (event.oldEnabled && !event.newEnabled) return "Disabled";
  return "Changed";
}

onMounted(() => {
  void refresh();
});
</script>

<template>
  <section class="capability-settings" aria-label="Agent capability permissions">
    <header class="capability-header">
      <div>
        <h3>Capabilities</h3>
        <p>
          Control which governed capabilities Vita Agent may request for the current Life.
          Enabling a capability changes only its root permission.
        </p>
      </div>
      <button type="button" :disabled="busy || loading" @click="refresh">Refresh</button>
    </header>

    <p class="capability-explain">
      Root enabled is not automatic execution. Even when a capability is enabled, every use still
      requires an eligible workspace scope, your explicit per-action confirmation, a Host-issued
      single-use grant, and a final revalidation immediately before the operation.
    </p>

    <p v-if="loading" class="capability-muted" aria-live="polite">Loading capability permissions…</p>

    <p v-if="error" class="capability-error" role="alert">{{ error }}</p>
    <p v-if="error && lifeUnavailable" class="capability-muted">
      Capability permissions are scoped to the current Life, so no capability can be listed or
      changed until Life setup is complete.
    </p>

    <p v-if="notice" class="capability-notice" aria-live="polite">{{ notice }}</p>

    <p v-if="snapshot" class="capability-life" aria-label="Current Life">
      Permissions for current Life: <code>{{ snapshot.lifeId }}</code>
    </p>

    <p v-if="!loading && capabilities.length === 0 && !error" class="capability-muted">
      No governed capabilities are available for this Life.
    </p>

    <article
      v-for="entry in capabilities"
      :key="entry.capabilityId"
      class="capability-card"
      :data-capability-id="entry.capabilityId"
    >
      <header class="capability-card-header">
        <div>
          <h4>{{ entry.displayName }}</h4>
          <code class="capability-id">{{ entry.capabilityId }}</code>
        </div>
        <span class="capability-state" :class="{ enabled: entry.enabled }">
          {{ entry.enabled ? "Root enabled" : "Root disabled" }}
        </span>
      </header>

      <p class="capability-description">{{ capabilityDescription(entry.capabilityId) }}</p>

      <dl class="capability-meta">
        <div><dt>Risk</dt><dd>{{ entry.riskClass }}</dd></div>
        <div><dt>Approval floor</dt><dd>{{ entry.approvalFloor }}</dd></div>
        <div><dt>Scope</dt><dd>{{ entry.scopeRequirement }}</dd></div>
        <div><dt>Access</dt><dd>{{ entry.readOnly ? "Read only" : "Writes data" }}</dd></div>
        <div><dt>Revision</dt><dd>{{ entry.revision }}</dd></div>
        <div><dt>Last updated</dt><dd>{{ lastUpdated(entry) }}</dd></div>
      </dl>

      <p
        v-if="requiresCriticalAcknowledgement(entry)"
        class="capability-warning"
        :data-warning-for="entry.capabilityId"
      >
        Critical capability with an explicit per-action approval floor. Enabling does not lower the
        risk class, the approval floor, or the workspace scope requirement, and it never authorizes
        a single action on its own.
      </p>

      <div class="capability-actions">
        <button
          v-if="!entry.enabled"
          type="button"
          class="primary"
          :disabled="busy"
          @click="requestEnable(entry)"
        >
          Enable capability…
        </button>
        <button
          v-else
          type="button"
          :disabled="busy"
          @click="disableCapability(entry)"
        >
          Disable capability
        </button>
      </div>

      <section class="capability-audit" aria-label="Authorization history">
        <strong>Authorization history</strong>
        <p v-if="entry.recentAuthorizationEvents.length === 0" class="capability-muted">
          No authorization changes have been recorded for this capability.
        </p>
        <ul v-else>
          <li
            v-for="event in entry.recentAuthorizationEvents"
            :key="`${entry.capabilityId}-${event.newRevision}`"
          >
            <span class="capability-audit-transition">
              {{ transitionLabel(event) }}
            </span>
            <span>revision {{ event.oldRevision }} → {{ event.newRevision }}</span>
            <span class="capability-muted">{{ eventTime(event.changedAt) }}</span>
            <span class="capability-muted">{{ event.actorKind }} · {{ event.provenanceKind }}</span>
          </li>
        </ul>
        <p class="capability-muted">
          Enable and disable changes are recorded as immutable audit events.
        </p>
      </section>
    </article>

    <section
      v-if="pendingEnableEntry"
      class="capability-confirmation"
      aria-label="Enable capability confirmation"
    >
      <strong>Enable {{ pendingEnableEntry.displayName }}?</strong>
      <p>
        This permits Vita Agent to request this {{ pendingEnableEntry.readOnly ? "read-only " : "" }}capability.
        Each use will still require your explicit confirmation.
        You can disable it at any time.
      </p>
      <p class="capability-meta-line">
        Risk {{ pendingEnableEntry.riskClass }} · Approval {{ pendingEnableEntry.approvalFloor }} · Scope
        {{ pendingEnableEntry.scopeRequirement }}
      </p>
      <label class="capability-ack">
        <input
          type="checkbox"
          :checked="pendingEnableAcknowledged"
          @change="pendingEnableAcknowledged = ($event.target as HTMLInputElement).checked"
        />
        I understand that enabling does not authorize any individual action.
      </label>
      <div class="capability-actions">
        <button
          type="button"
          class="primary"
          :disabled="busy || !pendingEnableAcknowledged"
          @click="confirmEnable"
        >
          Enable capability
        </button>
        <button type="button" :disabled="busy" @click="cancelEnable">Cancel</button>
      </div>
    </section>
  </section>
</template>

<style scoped>
.capability-settings { display: grid; gap: 0.85rem; }
.capability-header { display: flex; justify-content: space-between; gap: 1rem; align-items: start; }
.capability-header h3, .capability-header p { margin: 0; }
.capability-header p { color: #cbd5e1; font-size: 0.9rem; }
.capability-explain { margin: 0; color: #cbd5e1; font-size: 0.9rem; border-left: 3px solid #22d3ee; padding-left: 0.75rem; }
.capability-life { margin: 0; color: #e2e8f0; font-size: 0.9rem; }
.capability-card { display: grid; gap: 0.6rem; border: 1px solid #475569; border-radius: 0.7rem; padding: 1rem; background: #111c2e; }
.capability-card-header { display: flex; justify-content: space-between; gap: 1rem; align-items: start; }
.capability-card-header h4, .capability-card-header p { margin: 0; }
.capability-id { color: #94a3b8; font-size: 0.85rem; }
.capability-state { color: #fca5a5; font-size: 0.85rem; }
.capability-state.enabled { color: #67e8f9; }
.capability-description { margin: 0; color: #e2e8f0; font-size: 0.9rem; }
.capability-meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(9rem, 1fr)); gap: 0.4rem 1rem; margin: 0; }
.capability-meta div { display: grid; }
.capability-meta dt { color: #94a3b8; font-size: 0.75rem; text-transform: uppercase; }
.capability-meta dd { margin: 0; font-size: 0.9rem; }
.capability-meta-line { margin: 0; color: #cbd5e1; font-size: 0.85rem; }
.capability-warning { margin: 0; border: 1px solid #f59e0b; border-radius: 0.5rem; padding: 0.6rem; color: #fde68a; font-size: 0.85rem; }
.capability-actions { display: flex; flex-wrap: wrap; gap: 0.5rem; }
.capability-audit { display: grid; gap: 0.35rem; border-top: 1px solid #334155; padding-top: 0.6rem; }
.capability-audit ul { list-style: none; margin: 0; padding: 0; display: grid; gap: 0.3rem; }
.capability-audit li { display: flex; flex-wrap: wrap; gap: 0.75rem; font-size: 0.85rem; }
.capability-audit-transition { color: #e2e8f0; }
.capability-muted { color: #94a3b8; font-size: 0.85rem; margin: 0; }
.capability-error { color: #fecaca; margin: 0; }
.capability-notice { color: #fde68a; margin: 0; }
.capability-confirmation { display: grid; gap: 0.5rem; border: 1px solid #f59e0b; border-radius: 0.5rem; padding: 0.85rem; color: #fde68a; }
.capability-ack { display: flex; gap: 0.5rem; align-items: center; font-size: 0.85rem; }
@media (max-width: 620px) { .capability-header, .capability-card-header { flex-direction: column; align-items: stretch; } }
</style>
