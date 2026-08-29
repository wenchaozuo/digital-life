<script setup lang="ts">
import { computed, onMounted, ref } from "vue";

import type { LifeIdentity } from "../../life";
import { storageService } from "../../storage";
import {
  screenCaptureErrorFromUnknown,
  screenCaptureSettingsService,
  type ScreenCaptureSettingsError,
  type ScreenCaptureSmoke,
  type ScreenCaptureTargetDescriptor,
} from "./screenCaptureService";
import {
  screenPerceptionErrorFromUnknown,
  screenPerceptionSettingsService,
  type ScreenPerceptionPolicy,
  type ScreenPerceptionSessionStatus,
  type ScreenPerceptionSettingsError,
} from "./screenPerceptionSettingsService";

type ScreenPerceptionSettingsPhase = "loading" | "ready" | "failed";

const currentLife = ref<LifeIdentity>();
const policy = ref<ScreenPerceptionPolicy | null>();
const session = ref<ScreenPerceptionSessionStatus>();
const phase = ref<ScreenPerceptionSettingsPhase>("loading");
const loading = ref(false);
const error = ref<ScreenPerceptionSettingsError>();
const operation = ref("");

// Capture-target selection state (process-local, de-identified).
const targets = ref<ScreenCaptureTargetDescriptor[]>([]);
const selectedTarget = ref<ScreenCaptureTargetDescriptor | null>(null);
const targetError = ref<ScreenCaptureSettingsError>();
const targetOperation = ref("");
const targetLoading = ref(false);
const smoke = ref<ScreenCaptureSmoke>();

const sessionLifeId = computed(() =>
  session.value?.status === "armed" ? session.value.lifeId : undefined,
);
const sessionActiveForCurrentLife = computed(
  () =>
    Boolean(
      currentLife.value &&
        policy.value?.enabled &&
        session.value?.status === "armed" &&
        session.value.lifeId === currentLife.value.id,
    ),
);
const sessionMismatch = computed(
  () =>
    Boolean(
      currentLife.value &&
        session.value?.status === "armed" &&
        session.value.lifeId !== currentLife.value.id,
    ),
);
const canArm = computed(
  () =>
    phase.value === "ready" &&
    !loading.value &&
    Boolean(currentLife.value && policy.value?.enabled) &&
    !sessionActiveForCurrentLife.value,
);
const canSelectTarget = computed(
  () =>
    Boolean(currentLife.value) &&
    sessionActiveForCurrentLife.value &&
    !targetLoading.value,
);
const consentLabel = computed(() => {
  if (!currentLife.value) return "No current Life";
  if (!policy.value) return "Not configured";
  return policy.value.enabled ? "Enabled" : "Disabled";
});
const sessionLabel = computed(() => {
  if (phase.value === "loading") return "Loading…";
  if (!session.value) return "Unavailable";
  if (sessionActiveForCurrentLife.value) return "Armed for this Life";
  if (session.value.status === "armed") return "Armed for another Life";
  if (policy.value && !policy.value.enabled) return "Not active (consent disabled)";
  return "Disarmed";
});

async function refresh(): Promise<void> {
  phase.value = "loading";
  loading.value = true;
  error.value = undefined;
  operation.value = "";
  try {
    const life = await storageService.getCurrentLife();
    currentLife.value = life;
    const [loadedPolicy, loadedSession] = await Promise.all([
      life
        ? screenPerceptionSettingsService.getPolicy(life.id)
        : Promise.resolve(null),
      screenPerceptionSettingsService.getSessionStatus(),
    ]);
    policy.value = loadedPolicy;
    session.value = loadedSession;
    phase.value = "ready";
    await refreshTargetStatus();
  } catch (caught) {
    error.value = screenPerceptionErrorFromUnknown(caught);
    phase.value = "failed";
  } finally {
    loading.value = false;
  }
}

async function refreshTargetStatus(): Promise<void> {
  try {
    const status = await screenCaptureSettingsService.getTargetStatus();
    selectedTarget.value = status.selected;
  } catch (caught) {
    targetError.value = screenCaptureErrorFromUnknown(caught);
  }
}

async function enableConsent(): Promise<void> {
  const life = currentLife.value;
  if (!life || loading.value) return;

  loading.value = true;
  error.value = undefined;
  operation.value = "";
  try {
    policy.value = policy.value
      ? await screenPerceptionSettingsService.updatePolicy(
          life.id,
          true,
          policy.value.revision,
        )
      : await screenPerceptionSettingsService.createPolicy(life.id, true);
    phase.value = "ready";
    operation.value =
      "Persistent consent enabled. Arm this application session explicitly when ready.";
  } catch (caught) {
    error.value = screenPerceptionErrorFromUnknown(caught);
    phase.value = "failed";
  } finally {
    loading.value = false;
  }
}

async function disableConsent(): Promise<void> {
  const life = currentLife.value;
  const currentPolicy = policy.value;
  if (!life || !currentPolicy?.enabled || loading.value) return;

  loading.value = true;
  error.value = undefined;
  operation.value = "";
  try {
    policy.value = await screenPerceptionSettingsService.updatePolicy(
      life.id,
      false,
      currentPolicy.revision,
    );
    session.value = await screenPerceptionSettingsService.getSessionStatus();
    phase.value = "ready";
    operation.value = "Persistent consent disabled.";
  } catch (caught) {
    error.value = screenPerceptionErrorFromUnknown(caught);
    phase.value = "failed";
  } finally {
    loading.value = false;
  }
}

async function armSession(): Promise<void> {
  const life = currentLife.value;
  if (!life || !canArm.value) return;

  loading.value = true;
  error.value = undefined;
  operation.value = "";
  try {
    session.value = await screenPerceptionSettingsService.armSession(life.id);
    phase.value = "ready";
    operation.value = "Screen perception is armed for this application session.";
    await refreshTargetStatus();
  } catch (caught) {
    error.value = screenPerceptionErrorFromUnknown(caught);
    phase.value = "failed";
  } finally {
    loading.value = false;
  }
}

async function disarmSession(): Promise<void> {
  if (loading.value || session.value?.status !== "armed") return;

  loading.value = true;
  error.value = undefined;
  operation.value = "";
  try {
    session.value = await screenPerceptionSettingsService.disarmSession();
    phase.value = "ready";
    operation.value = "Screen perception is disarmed for this application session.";
    await refreshTargetStatus();
  } catch (caught) {
    error.value = screenPerceptionErrorFromUnknown(caught);
    phase.value = "failed";
  } finally {
    loading.value = false;
  }
}

async function loadTargets(): Promise<void> {
  const life = currentLife.value;
  if (!life || !canSelectTarget.value) return;

  targetLoading.value = true;
  targetError.value = undefined;
  targetOperation.value = "";
  try {
    targets.value = await screenCaptureSettingsService.listTargets();
    targetOperation.value =
      targets.value.length > 0
        ? "Choose a window or monitor from the list to select a capture target."
        : "No capture targets are available on this device.";
  } catch (caught) {
    targetError.value = screenCaptureErrorFromUnknown(caught);
  } finally {
    targetLoading.value = false;
  }
}

async function selectTarget(index: number): Promise<void> {
  const life = currentLife.value;
  if (!life || targetLoading.value) return;

  targetLoading.value = true;
  targetError.value = undefined;
  targetOperation.value = "";
  try {
    selectedTarget.value = await screenCaptureSettingsService.selectTarget(
      life.id,
      index,
    );
    targetOperation.value = "Capture target selected for this session.";
  } catch (caught) {
    targetError.value = screenCaptureErrorFromUnknown(caught);
  } finally {
    targetLoading.value = false;
  }
}

async function clearTarget(): Promise<void> {
  if (targetLoading.value) return;
  targetLoading.value = true;
  targetError.value = undefined;
  targetOperation.value = "";
  try {
    const status = await screenCaptureSettingsService.clearTarget();
    selectedTarget.value = status.selected;
    targetOperation.value = "Capture target cleared for this session.";
  } catch (caught) {
    targetError.value = screenCaptureErrorFromUnknown(caught);
  } finally {
    targetLoading.value = false;
  }
}

async function runSmokeCapture(): Promise<void> {
  const life = currentLife.value;
  if (!life || targetLoading.value) return;

  targetLoading.value = true;
  targetError.value = undefined;
  targetOperation.value = "";
  smoke.value = undefined;
  try {
    smoke.value = await screenCaptureSettingsService.captureSmoke(life.id);
    targetOperation.value =
      "One-shot capture succeeded (metadata only; pixels are never shown or stored).";
  } catch (caught) {
    targetError.value = screenCaptureErrorFromUnknown(caught);
  } finally {
    targetLoading.value = false;
  }
}

onMounted(() => {
  void refresh();
});
</script>

<template>
  <section class="settings-section screen-perception-settings" aria-label="Screen perception settings">
    <section class="result" aria-label="Screen perception privacy status">
      <h2>Screen perception privacy</h2>
      <p>
        Persistent consent and session activation are separate. This section only controls permission;
        it does not capture your screen.
      </p>
      <dl>
        <div>
          <dt>Current Life</dt>
          <dd data-testid="screen-perception-current-life">{{ currentLife?.name ?? "No Life selected" }}</dd>
        </div>
        <div>
          <dt>Persistent consent</dt>
          <dd data-testid="screen-perception-consent">{{ consentLabel }}</dd>
        </div>
        <div v-if="policy">
          <dt>Consent revision</dt>
          <dd data-testid="screen-perception-revision">{{ policy.revision }}</dd>
        </div>
        <div>
          <dt>Application session</dt>
          <dd data-testid="screen-perception-session">{{ sessionLabel }}</dd>
        </div>
      </dl>
      <p v-if="phase === 'loading'" class="phase" data-testid="screen-perception-loading" role="status">
        Loading screen perception settings…
      </p>
      <p v-else-if="!currentLife" class="phase" data-testid="screen-perception-no-life">
        Create or restore a Life before configuring screen perception.
      </p>
      <p v-else-if="!policy" class="phase" data-testid="screen-perception-no-policy">
        No durable consent is configured for this Life.
      </p>
      <p v-if="sessionMismatch" class="phase mismatch" data-testid="screen-perception-life-mismatch">
        The current session is armed for another Life and is not active for this Life.
      </p>
    </section>

    <div class="actions" aria-label="Screen perception consent actions">
      <button
        v-if="!policy || !policy.enabled"
        type="button"
        class="primary"
        data-testid="screen-perception-enable"
        :disabled="loading || !currentLife"
        @click="enableConsent"
      >
        Enable persistent consent
      </button>
      <button
        v-else
        type="button"
        class="danger"
        data-testid="screen-perception-disable"
        :disabled="loading"
        @click="disableConsent"
      >
        Disable persistent consent
      </button>

      <button
        v-if="session?.status === 'armed'"
        type="button"
        data-testid="screen-perception-disarm"
        :disabled="loading"
        @click="disarmSession"
      >
        Disarm this session
      </button>
      <button
        v-if="canArm"
        type="button"
        class="primary"
        data-testid="screen-perception-arm"
        :disabled="loading"
        @click="armSession"
      >
        Arm this session
      </button>
      <button
        type="button"
        data-testid="screen-perception-refresh"
        :disabled="loading"
        @click="refresh"
      >
        Refresh status
      </button>
    </div>

    <p v-if="operation" class="phase" data-testid="screen-perception-operation" role="status">
      {{ operation }}
    </p>

    <section v-if="error" class="result error" data-testid="screen-perception-error" aria-live="polite">
      <strong>{{ error.code }}</strong>
      <p>{{ error.message }}</p>
      <p v-if="error.code === 'SCREEN_PERCEPTION_REVISION_CONFLICT'">
        Refresh the policy and retry the action.
      </p>
    </section>

    <p v-if="sessionLifeId && sessionMismatch" class="phase" data-testid="screen-perception-armed-life">
      Session owner: {{ sessionLifeId }}
    </p>

    <section class="result" aria-label="Screen capture target" data-testid="screen-capture-target-section">
      <h2>Capture target (this session only)</h2>
      <p>
        Selecting a target does not create or change consent. The target exists only in this
        process and is cleared when the application restarts.
      </p>
      <dl>
        <div>
          <dt>Current target</dt>
          <dd data-testid="screen-capture-target-status">
            {{ selectedTarget ? `${selectedTarget.label}` : "None" }}
          </dd>
        </div>
        <div v-if="smoke">
          <dt>Last one-shot smoke capture</dt>
          <dd data-testid="screen-capture-smoke">
            {{ smoke.width }}×{{ smoke.height }} {{ smoke.pixelFormat }} (metadata only)
          </dd>
        </div>
      </dl>

      <div class="actions" aria-label="Screen capture target actions">
        <button
          type="button"
          data-testid="screen-capture-list-targets"
          :disabled="!canSelectTarget || targetLoading"
          @click="loadTargets"
        >
          List capture targets
        </button>
        <button
          type="button"
          data-testid="screen-capture-clear-target"
          :disabled="!selectedTarget || targetLoading"
          @click="clearTarget"
        >
          Clear target
        </button>
        <button
          type="button"
          class="primary"
          data-testid="screen-capture-smoke"
          :disabled="!selectedTarget || !sessionActiveForCurrentLife || targetLoading"
          @click="runSmokeCapture"
        >
          One-shot capture smoke test
        </button>
      </div>

      <p v-if="targets.length > 0" class="phase">
        Select a de-identified target:
      </p>
      <ul class="target-list" aria-label="Available capture targets">
        <li v-for="target in targets" :key="target.index">
          <button
            type="button"
            data-testid="screen-capture-target-option"
            :disabled="!canSelectTarget || targetLoading"
            @click="selectTarget(target.index)"
          >
            {{ target.label }}
          </button>
        </li>
      </ul>

      <p v-if="targetOperation" class="phase" data-testid="screen-capture-operation" role="status">
        {{ targetOperation }}
      </p>
      <section v-if="targetError" class="result error" data-testid="screen-capture-error" aria-live="polite">
        <strong>{{ targetError.code }}</strong>
        <p>{{ targetError.message }}</p>
      </section>
    </section>
  </section>
</template>

<style scoped>
.screen-perception-settings { display: grid; gap: 1rem; }
.screen-perception-settings dl { display: grid; gap: 0.6rem; margin: 0; }
.screen-perception-settings dl div { display: grid; gap: 0.2rem; }
.screen-perception-settings dt { color: #94a3b8; font-size: 0.85rem; }
.screen-perception-settings dd { margin: 0; }
.screen-perception-settings .actions { display: flex; flex-wrap: wrap; gap: 0.65rem; }
.screen-perception-settings .mismatch { color: #fbbf24; }
.screen-perception-settings .target-list { list-style: none; margin: 0; padding: 0; display: grid; gap: 0.4rem; }
.screen-perception-settings .target-list button { text-align: left; }
</style>
