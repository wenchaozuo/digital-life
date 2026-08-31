<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";

import type { LifeIdentity } from "../../life";
import { storageService } from "../../storage";
import {
  screenCaptureErrorFromUnknown,
  screenCaptureSettingsService,
  type ScreenCaptureSettingsError,
  type ScreenCaptureSmoke,
  type ScreenCaptureTargetStatus,
} from "./screenCaptureService";
import {
  screenPerceptionErrorFromUnknown,
  screenPerceptionSettingsService,
  type ScreenPerceptionPolicy,
  type ScreenPerceptionSessionStatus,
  type ScreenPerceptionSettingsError,
} from "./screenPerceptionSettingsService";
import {
  screenVisionOutboundErrorFromUnknown,
  screenVisionOutboundSettingsService,
  type ScreenVisionOutboundPolicy,
  type ScreenVisionOutboundSettingsError,
} from "./screenVisionOutboundSettingsService";

type ScreenPerceptionSettingsPhase = "loading" | "ready" | "failed";
type ScreenVisionOutboundSettingsPhase = "loading" | "ready" | "failed";

const currentLife = ref<LifeIdentity>();
const policy = ref<ScreenPerceptionPolicy | null>();
const session = ref<ScreenPerceptionSessionStatus>();
const phase = ref<ScreenPerceptionSettingsPhase>("loading");
const loading = ref(false);
const error = ref<ScreenPerceptionSettingsError>();
const operation = ref("");

// Capture-target selection state (process-local, bounded status only).
const targetStatus = ref<ScreenCaptureTargetStatus>();
const targetError = ref<ScreenCaptureSettingsError>();
const targetOperation = ref("");
const targetLoading = ref(false);
const smoke = ref<ScreenCaptureSmoke>();

const outboundPolicy = ref<ScreenVisionOutboundPolicy | null>();
const outboundPhase = ref<ScreenVisionOutboundSettingsPhase>("loading");
const outboundLoading = ref(false);
const outboundError = ref<ScreenVisionOutboundSettingsError>();
const outboundOperation = ref("");

let componentEpoch = 0;
let refreshGeneration = 0;
let outboundMutationGeneration = 0;

const targetSelected = computed(
  () => targetStatus.value?.status === "selected",
);

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

const outboundConsentLabel = computed(() => {
  if (!currentLife.value) return "No current Life";
  if (outboundPhase.value === "loading") return "Loading…";
  if (outboundPolicy.value === undefined) return "Unavailable";
  return outboundPolicy.value?.enabled ? "Enabled" : "Disabled";
});

const sessionLabel = computed(() => {
  if (phase.value === "loading") return "Loading…";
  if (!session.value) return "Unavailable";
  if (sessionActiveForCurrentLife.value) return "Armed for this Life";
  if (session.value.status === "armed") return "Armed for another Life";
  if (policy.value && !policy.value.enabled) return "Not active (consent disabled)";
  return "Disarmed";
});

function isCurrentRefresh(
  epoch: number,
  generation: number,
  lifeId?: string,
): boolean {
  return (
    componentEpoch === epoch &&
    refreshGeneration === generation &&
    (lifeId === undefined || currentLife.value?.id === lifeId)
  );
}

function isCurrentOutboundMutation(
  epoch: number,
  generation: number,
  lifeId: string,
): boolean {
  return (
    componentEpoch === epoch &&
    outboundMutationGeneration === generation &&
    currentLife.value?.id === lifeId
  );
}

async function refresh(): Promise<void> {
  const epoch = componentEpoch;
  const generation = ++refreshGeneration;
  phase.value = "loading";
  loading.value = true;
  error.value = undefined;
  operation.value = "";
  outboundPhase.value = "loading";
  outboundError.value = undefined;
  outboundOperation.value = "";
  try {
    const life = await storageService.getCurrentLife();
    if (!isCurrentRefresh(epoch, generation)) return;

    currentLife.value = life;

    const perceptionLoad = Promise.all([
      life
        ? screenPerceptionSettingsService.getPolicy(life.id)
        : Promise.resolve(null),
      screenPerceptionSettingsService.getSessionStatus(),
    ]);
    const outboundLoad = life
      ? screenVisionOutboundSettingsService.getPolicy(life.id)
      : Promise.resolve(null);
    const [perceptionResult] = await Promise.allSettled([perceptionLoad]);
    if (isCurrentRefresh(epoch, generation, life?.id)) {
      if (perceptionResult.status === "fulfilled") {
        const [loadedPolicy, loadedSession] = perceptionResult.value;
        policy.value = loadedPolicy;
        session.value = loadedSession;
        phase.value = "ready";
      } else {
        error.value = screenPerceptionErrorFromUnknown(perceptionResult.reason);
        phase.value = "failed";
      }
      // D23 controls remain responsive while the independent D25 read is in flight.
      loading.value = false;
      await refreshTargetStatus(epoch, generation);
    }

    const [outboundResult] = await Promise.allSettled([outboundLoad]);
    if (isCurrentRefresh(epoch, generation, life?.id)) {
      if (outboundResult.status === "fulfilled") {
        outboundPolicy.value = outboundResult.value;
        outboundPhase.value = "ready";
      } else {
        outboundError.value = screenVisionOutboundErrorFromUnknown(
          outboundResult.reason,
        );
        outboundPhase.value = "failed";
      }
    }
  } catch (caught) {
    if (!isCurrentRefresh(epoch, generation)) return;
    error.value = screenPerceptionErrorFromUnknown(caught);
    phase.value = "failed";
    outboundError.value = screenVisionOutboundErrorFromUnknown(caught);
    outboundPhase.value = "failed";
  } finally {
    if (isCurrentRefresh(epoch, generation)) {
      loading.value = false;
    }
  }
}

async function refreshTargetStatus(
  epoch = componentEpoch,
  generation = refreshGeneration,
): Promise<void> {
  targetError.value = undefined;
  try {
    const loadedTargetStatus = await screenCaptureSettingsService.getTargetStatus();
    if (isCurrentRefresh(epoch, generation)) {
      targetStatus.value = loadedTargetStatus;
    }
  } catch (caught) {
    if (isCurrentRefresh(epoch, generation)) {
      targetError.value = screenCaptureErrorFromUnknown(caught);
    }
  }
}

async function rereadOutboundPolicyAfterUpdateFailure(
  lifeId: string,
  epoch: number,
  mutationGeneration: number,
  requestedEnabled: boolean,
  caught: unknown,
): Promise<void> {
  const updateError = screenVisionOutboundErrorFromUnknown(caught);
  try {
    const refreshedPolicy =
      await screenVisionOutboundSettingsService.getPolicy(lifeId);
    if (!isCurrentOutboundMutation(epoch, mutationGeneration, lifeId)) return;

    outboundPolicy.value = refreshedPolicy;
    outboundPhase.value = "ready";
    outboundError.value = updateError;
    outboundOperation.value =
      refreshedPolicy?.enabled === requestedEnabled
        ? "Current permission state was refreshed."
        : "The current permission state was refreshed. Review it before trying again.";
  } catch (refreshCaught) {
    if (!isCurrentOutboundMutation(epoch, mutationGeneration, lifeId)) return;

    outboundPhase.value = "failed";
    outboundError.value = screenVisionOutboundErrorFromUnknown(refreshCaught);
    outboundOperation.value =
      "The current permission state could not be refreshed. Retry before trying again.";
  }
}

async function updateOutboundConsent(enabled: boolean): Promise<void> {
  const life = currentLife.value;
  const existingPolicy = outboundPolicy.value;
  if (
    !life ||
    outboundLoading.value ||
    outboundPhase.value !== "ready" ||
    (!enabled && !existingPolicy?.enabled)
  ) {
    return;
  }

  const epoch = componentEpoch;
  const mutationGeneration = ++outboundMutationGeneration;
  outboundLoading.value = true;
  outboundError.value = undefined;
  outboundOperation.value = "";
  let updateAttempted = false;

  try {
    let policyForUpdate = existingPolicy;
    if (!policyForUpdate) {
      policyForUpdate = await screenVisionOutboundSettingsService.createPolicy(
        life.id,
      );
      if (!isCurrentOutboundMutation(epoch, mutationGeneration, life.id)) return;

      // Creation is deliberately disabled-only. The explicit user action then
      // performs the separate enabled transition using the returned revision.
      outboundPolicy.value = policyForUpdate;
    }

    if (!isCurrentOutboundMutation(epoch, mutationGeneration, life.id)) return;

    updateAttempted = true;
    const updatedPolicy = await screenVisionOutboundSettingsService.updatePolicy(
      life.id,
      enabled,
      policyForUpdate.revision,
    );
    if (!isCurrentOutboundMutation(epoch, mutationGeneration, life.id)) return;

    outboundPolicy.value = updatedPolicy;
    outboundPhase.value = "ready";
    outboundOperation.value = enabled
      ? "Screen image sharing permission enabled for this Life. Enabling this permission does not send any images by itself."
      : "Screen image sharing permission disabled for this Life.";
  } catch (caught) {
    if (!isCurrentOutboundMutation(epoch, mutationGeneration, life.id)) return;

    if (updateAttempted) {
      await rereadOutboundPolicyAfterUpdateFailure(
        life.id,
        epoch,
        mutationGeneration,
        enabled,
        caught,
      );
    } else {
      outboundPhase.value = "failed";
      outboundError.value = screenVisionOutboundErrorFromUnknown(caught);
    }
  } finally {
    if (
      componentEpoch === epoch &&
      outboundMutationGeneration === mutationGeneration
    ) {
      outboundLoading.value = false;
    }
  }
}

async function enableOutboundConsent(): Promise<void> {
  await updateOutboundConsent(true);
}

async function disableOutboundConsent(): Promise<void> {
  await updateOutboundConsent(false);
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

async function pickTarget(): Promise<void> {
  const life = currentLife.value;
  if (!life || !canSelectTarget.value) return;

  targetLoading.value = true;
  targetError.value = undefined;
  targetOperation.value = "";
  try {
    const pick = await screenCaptureSettingsService.pickTarget(life.id);
    targetStatus.value = pick.status === "selected" ? { status: "selected" } : { status: "none" };
    if (pick.cancelled) {
      targetOperation.value = "Target picker closed without a selection. The previous target is unchanged.";
    } else if (pick.status === "selected") {
      targetOperation.value = "A capture target was selected in the Windows system picker for this session.";
    } else {
      targetOperation.value = "No capture target is selected.";
    }
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
    targetStatus.value = await screenCaptureSettingsService.clearTarget();
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
  componentEpoch += 1;
  void refresh();
});

onUnmounted(() => {
  componentEpoch += 1;
  refreshGeneration += 1;
  outboundMutationGeneration += 1;
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
        :disabled="loading || outboundLoading"
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

    <section
      class="result screen-vision-outbound-settings"
      aria-label="Screen image sharing for Vision"
      data-testid="screen-vision-outbound-section"
    >
      <h2>Screen image sharing for Vision</h2>
      <p>
        This is separate from local screen perception. It allows this Life to authorize a future
        explicit network transmission of a privacy-reviewed screen image to a configured Vision provider.
      </p>
      <dl>
        <div>
          <dt>Screen image sharing permission</dt>
          <dd data-testid="screen-vision-outbound-status">{{ outboundConsentLabel }}</dd>
        </div>
        <div v-if="outboundPolicy">
          <dt>Permission revision</dt>
          <dd data-testid="screen-vision-outbound-revision">{{ outboundPolicy.revision }}</dd>
        </div>
      </dl>
      <p class="important">
        Enabling this permission does not send any images by itself.
      </p>
      <p>Cloud Vision image transmission is not active yet.</p>
      <p v-if="outboundPolicy?.enabled" data-testid="screen-vision-outbound-enabled-copy">
        This permission only allows a future explicit Vision action to become eligible. No screen
        image is being uploaded by this setting alone.
      </p>
      <p v-if="outboundPhase === 'loading'" class="phase" data-testid="screen-vision-outbound-loading" role="status">
        Loading screen image sharing settings…
      </p>
      <p v-else-if="!currentLife" class="phase" data-testid="screen-vision-outbound-no-life">
        Create or restore a Life before configuring screen image sharing.
      </p>
      <p v-else-if="outboundPolicy === null" class="phase" data-testid="screen-vision-outbound-no-policy">
        No screen-image sharing permission has been granted for this Life.
      </p>
      <p v-else-if="outboundPolicy === undefined" class="phase" data-testid="screen-vision-outbound-unavailable">
        The current screen image sharing permission could not be loaded. Refresh to try again.
      </p>

      <div class="actions" aria-label="Screen image sharing permission actions">
        <button
          v-if="!outboundPolicy?.enabled"
          type="button"
          class="primary"
          data-testid="screen-vision-outbound-enable"
          :disabled="outboundLoading || outboundPhase !== 'ready' || !currentLife"
          @click="enableOutboundConsent"
        >
          Enable screen image sharing
        </button>
        <button
          v-else
          type="button"
          class="danger"
          data-testid="screen-vision-outbound-disable"
          :disabled="outboundLoading || outboundPhase !== 'ready'"
          @click="disableOutboundConsent"
        >
          Disable screen image sharing
        </button>
      </div>
      <p v-if="outboundOperation" class="phase" data-testid="screen-vision-outbound-operation" role="status">
        {{ outboundOperation }}
      </p>
      <section v-if="outboundError" class="result error" data-testid="screen-vision-outbound-error" aria-live="polite">
        <strong>{{ outboundError.code }}</strong>
        <p>{{ outboundError.message }}</p>
        <p
          v-if="outboundError.code === 'SCREEN_VISION_OUTBOUND_REVISION_CONFLICT' || outboundError.code === 'SCREEN_VISION_OUTBOUND_POLICY_EVENT_CONFLICT'"
        >
          The latest permission state has been refreshed. Do not retry automatically; review the current state first.
        </p>
      </section>
    </section>

    <section class="result" aria-label="Screen capture target" data-testid="screen-capture-target-section">
      <h2>Capture target (this session only)</h2>
      <p>
        Selecting a target does not create or change consent. You pick the window or display in the
        Windows system picker; the target exists only in this process and is cleared when the
        application restarts.
      </p>
      <dl>
        <div>
          <dt>Current target</dt>
          <dd data-testid="screen-capture-target-status">
            {{ targetSelected ? "Selected" : "None" }}
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
          class="primary"
          data-testid="screen-capture-pick-target"
          :disabled="!canSelectTarget || targetLoading"
          @click="pickTarget"
        >
          Pick capture target…
        </button>
        <button
          type="button"
          data-testid="screen-capture-clear-target"
          :disabled="!targetSelected || targetLoading"
          @click="clearTarget"
        >
          Clear target
        </button>
        <button
          type="button"
          data-testid="screen-capture-smoke"
          :disabled="!targetSelected || !sessionActiveForCurrentLife || targetLoading"
          @click="runSmokeCapture"
        >
          One-shot capture smoke test
        </button>
      </div>

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
.screen-vision-outbound-settings { border-color: #475569; }
.screen-vision-outbound-settings .important { color: #fde68a; font-weight: 700; }
</style>
