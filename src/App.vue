<script setup lang="ts">
import { invoke } from "@tauri-apps/api/core";
import { computed, onMounted, onUnmounted, ref } from "vue";
import {
  BodyBindingChangedListenerLifecycle,
  BodyExpressionListenerLifecycle,
  BodyRuntimeBindingController,
  bodyBindingChangedBridge,
  bodyExpressionBridge,
  bodyStateMachine,
  bodyPackageService,
  createBodyPresentationForBodyId,
  installManagedBodyPackageRegistrySnapshot,
  type BodyState,
} from "./body";
import { initializeDefaultLife, type LifeIdentity } from "./life";
import { personaManager, type PersonaTemplate } from "./persona";
import {
  mainScreenObservationService,
  screenObservationErrorFromUnknown,
  type MainScreenContextGrant,
  type MainScreenObservation,
  type MainScreenObservationError,
  type MainScreenPerceptionStatus,
} from "./perception/screenObservationService";
import {
  createSecureVisionAttemptId,
  mainScreenVisionDeliveryService,
  screenVisionDeliveryErrorFromUnknown,
  type MainScreenVisionAnalysis,
  type MainScreenVisionAttempt,
  type MainScreenVisionDeliveryError,
  type MainScreenVisionReview,
  type MainScreenVisionStatus,
} from "./perception/screenVisionDeliveryService";
import { storageService } from "./storage";

const bodyState = ref<BodyState>("idle");
const bodyRendererElement = ref<HTMLElement>();
const lifeIdentity = ref<LifeIdentity>();
const personaTemplate = ref<PersonaTemplate>();
const settingsError = ref("");
const screenPerceptionStatus = ref<MainScreenPerceptionStatus>();
const screenObservation = ref<MainScreenObservation>();
const screenObservationError = ref<MainScreenObservationError>();
const screenObservationLoading = ref(false);
const screenContextGrant = ref<MainScreenContextGrant>();
const screenContextGrantLifeId = ref<string>();
const screenContextAttachmentId = ref<string>();
const screenPreparedCandidateId = ref<string>();
const screenContextPreparing = ref(false);
const screenVisionStatus = ref<MainScreenVisionStatus>();
const screenVisionReview = ref<MainScreenVisionReview>();
const screenVisionResult = ref<MainScreenVisionAnalysis>();
const screenVisionError = ref<MainScreenVisionDeliveryError>();
const screenVisionPreparing = ref(false);
const screenVisionSending = ref(false);
const screenVisionAbandoning = ref(false);
const screenVisionOffering = ref(false);
const screenVisionAttempt = ref<MainScreenVisionAttempt>();
let unsubscribe: (() => void) | undefined;
let bodyRuntimeBinding: BodyRuntimeBindingController | undefined;
let lifecycleEpoch = 0;
let screenStatusRequestGeneration = 0;
let screenObservationRequestGeneration = 0;
let screenHandoffRequestGeneration = 0;
let screenVisionStatusRequestGeneration = 0;
let screenVisionRequestGeneration = 0;
const SCREEN_VISION_TERMINAL_SETTLEMENT_ERROR_CODE =
  "VISION_TERMINAL_SETTLEMENT_UNAVAILABLE_AFTER_SEND";

const screenReadinessLabel = computed(() => {
  if (screenObservationLoading.value) {
    return "Observing";
  }
  const status = screenPerceptionStatus.value;
  if (status === undefined || !status.consentEnabled) {
    return "Needs setup";
  }
  if (!status.sessionArmed) {
    return "Disarmed";
  }
  if (!status.targetSelected) {
    return "No target";
  }
  return status.ready ? "Ready" : "Not ready";
});

const canObserveScreen = computed(
  () =>
    lifeIdentity.value !== undefined &&
    screenPerceptionStatus.value?.targetSelected === true &&
    screenPerceptionStatus.value?.ready === true &&
    !screenObservationLoading.value,
);

const screenObservationPrepared = computed(() => {
  const observation = screenObservation.value;
  return (
    observation?.status === "recognized" &&
    screenContextAttachmentId.value !== undefined &&
    screenPreparedCandidateId.value === observation.candidateId
  );
});

const screenContextCleanupRequired = computed(() => {
  const observation = screenObservation.value;
  return (
    observation?.status === "recognized" &&
    screenContextGrant.value !== undefined &&
    screenContextGrantLifeId.value === lifeIdentity.value?.id &&
    screenPreparedCandidateId.value === observation.candidateId &&
    screenContextAttachmentId.value === undefined &&
    !screenContextPreparing.value
  );
});

const canUseScreenContextAction = computed(
  () =>
    screenObservation.value?.status === "recognized" &&
    (!screenObservationPrepared.value || screenContextCleanupRequired.value) &&
    !screenContextPreparing.value,
);

const screenVisionReviewForDisplay = computed<MainScreenVisionReview | undefined>(
  () => {
    const status = screenVisionStatus.value;
    if (status !== undefined) {
      // Backend status is the authoritative delivery lifecycle; its review is
      // the only review that may render.  An idle + null review must never let
      // a stale local review survive on screen.
      return status.review ?? undefined;
    }
    // No backend status yet: the local review may render only during the
    // prepare transition, never as a retained stale review.
    return screenVisionPreparing.value ? screenVisionReview.value : undefined;
  },
);

const screenVisionDefiniteDeliveryObserved = computed(
  () =>
    screenVisionStatus.value?.status === "definiteDeliveryObserved" ||
    screenVisionError.value?.code === SCREEN_VISION_TERMINAL_SETTLEMENT_ERROR_CODE,
);

const screenVisionRetryAvailable = computed(
  () =>
    screenVisionStatus.value?.status === "awaitingRetryDecision" &&
    screenVisionStatus.value.review !== null &&
    screenVisionAttempt.value !== undefined &&
    screenVisionAttempt.value.reviewId === screenVisionStatus.value.review.reviewId,
);

const screenVisionCanPrepare = computed(() => {
  if (
    lifeIdentity.value === undefined ||
    screenVisionPreparing.value ||
    screenVisionSending.value ||
    screenVisionAbandoning.value
    || screenVisionOffering.value
  ) {
    return false;
  }
  const status = screenVisionStatus.value;
  if (status === undefined) {
    return true;
  }
  // Backend lifecycle authority: Prepare is allowed only when the backend is
  // idle or has a review-ready slot.  Committed (awaiting retry), in-flight,
  // and terminal deliveries are never replaced by a new preparation.
  return status.status === "idle" || status.status === "reviewReady";
});

const screenVisionCanSend = computed(() => {
  if (
    screenVisionPreparing.value ||
    screenVisionSending.value ||
    screenVisionAbandoning.value ||
    screenVisionOffering.value
  ) {
    return false;
  }
  const status = screenVisionStatus.value;
  if (status === undefined) {
    return false;
  }
  if (status.status === "reviewReady") {
    // New explicit confirmation: the exact frontend/backend review exists.
    return (
      status.review !== null &&
      screenVisionReview.value?.reviewId === status.review.reviewId
    );
  }
  if (status.status === "awaitingRetryDecision") {
    // Exact retry: the committed backend tuple must be bound locally.
    const attempt = screenVisionAttempt.value;
    return (
      status.review !== null &&
      attempt !== undefined &&
      attempt.reviewId === status.review.reviewId
    );
  }
  // idle, deliveryInProgress, definiteDeliveryObserved, and unknown status
  // never allow send, regardless of any local review.
  return false;
});

const screenVisionCanAbandon = computed(() => {
  const status = screenVisionStatus.value;
  return (
    status?.status === "awaitingRetryDecision" &&
    status.review !== null &&
    !screenVisionSending.value &&
    !screenVisionAbandoning.value
  );
});

const screenVisionCanUseInChat = computed(
  () =>
    screenVisionResult.value?.visionResultId !== null &&
    screenVisionResult.value?.visionResultId !== undefined &&
    !screenVisionPreparing.value &&
    !screenVisionSending.value &&
    !screenVisionAbandoning.value &&
    !screenVisionOffering.value,
);

// D17-C: the listener registration race with unmount is fenced by this
// controller, so a registration promise resolving after unmount is
// immediately unlistened.
const bodyExpressionListener = new BodyExpressionListenerLifecycle((handler) =>
  bodyExpressionBridge.listenForBodyExpression(handler),
);
const bodyBindingChangedListener = new BodyBindingChangedListenerLifecycle((handler) =>
  bodyBindingChangedBridge.listen(handler),
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

function revokePendingGrantWithoutPublishingError(lifeId: string, grantId: string): void {
  void mainScreenObservationService
    .revokeMainPendingScreenContextGrant(lifeId, grantId)
    .catch(() => {
      // The stale result is never applied.  A bounded status reread or a
      // later exact cleanup path remains authoritative for the backend grant.
    });
}

function clearLocalPendingGrant(lifeId: string, grantId: string): void {
  if (
    screenContextGrant.value?.grantId !== grantId ||
    screenContextGrantLifeId.value !== lifeId
  ) {
    return;
  }
  screenContextGrant.value = undefined;
  screenContextGrantLifeId.value = undefined;
  screenPreparedCandidateId.value = undefined;
}

function invalidateScreenHandoff(): void {
  const pendingGrant = screenContextGrant.value;
  const pendingGrantLifeId = screenContextGrantLifeId.value;
  screenHandoffRequestGeneration += 1;
  screenContextPreparing.value = false;
  screenContextGrant.value = undefined;
  screenContextGrantLifeId.value = undefined;
  screenContextAttachmentId.value = undefined;
  screenPreparedCandidateId.value = undefined;

  if (pendingGrant !== undefined && pendingGrantLifeId !== undefined) {
    revokePendingGrantWithoutPublishingError(pendingGrantLifeId, pendingGrant.grantId);
  }
}

function clearScreenObservation(): void {
  screenObservation.value = undefined;
  screenObservationError.value = undefined;
  invalidateScreenHandoff();
}

function isCurrentScreenVisionRequest(
  runtimeEpoch: number,
  lifeId: string,
  requestGeneration: number,
): boolean {
  return (
    isRuntimeActive(runtimeEpoch) &&
    lifeIdentity.value?.id === lifeId &&
    screenVisionRequestGeneration === requestGeneration
  );
}

function invalidateScreenVision(): void {
  screenVisionRequestGeneration += 1;
  screenVisionStatusRequestGeneration += 1;
  screenVisionStatus.value = undefined;
  screenVisionReview.value = undefined;
  screenVisionResult.value = undefined;
  screenVisionError.value = undefined;
  screenVisionAttempt.value = undefined;
  screenVisionPreparing.value = false;
  screenVisionSending.value = false;
  screenVisionAbandoning.value = false;
  screenVisionOffering.value = false;
}

// Backend ScreenVision status is the authoritative delivery lifecycle.
// A frontend error code is presentation/diagnosis only and never decides
// tuple destruction (D26-F1/F2).  This single rule reconciles every status
// refresh; catch/finally blocks must not re-implement lifecycle decisions.
function reconcileScreenVisionStatus(status: MainScreenVisionStatus): void {
  screenVisionStatus.value = status;
  const authoritativeReview = status.review;

  if (status.status === "idle" || authoritativeReview === null) {
    // Idle with null review: no review and no committed retry tuple can
    // survive.  This closes the stale-local-review bug (D26-F2).
    screenVisionReview.value = undefined;
    screenVisionAttempt.value = undefined;
    return;
  }

  // Backend review replaces any local review (display authority).
  screenVisionReview.value = authoritativeReview;

  if (status.status === "awaitingRetryDecision") {
    // A matching local attempt is the exact committed retry tuple bound to
    // this backend review.  Any other attempt belongs to a different review
    // and must not be reused (no invented recovery).
    if (
      screenVisionAttempt.value?.reviewId !== authoritativeReview.reviewId
    ) {
      screenVisionAttempt.value = undefined;
    }
    return;
  }

  if (status.status === "reviewReady") {
    // reviewReady has no committed retry-tuple authority: a previous failed
    // execute does not justify retaining an attempt for this review.  The
    // next explicit Analyze creates a fresh attempt.
    screenVisionAttempt.value = undefined;
    return;
  }

  if (status.status === "deliveryInProgress") {
    // Keep the exact matching attempt so the committed retry tuple survives
    // the in-flight window; no other local state may override the backend.
    if (screenVisionAttempt.value?.reviewId !== authoritativeReview.reviewId) {
      screenVisionAttempt.value = undefined;
    }
    return;
  }

  // definiteDeliveryObserved: the review stays for terminal display only.
  // The attempt tuple must not survive, and the terminal state is never
  // converted to idle.
  screenVisionAttempt.value = undefined;
}

async function refreshScreenVisionStatus(runtimeEpoch: number): Promise<void> {
  const lifeId = lifeIdentity.value?.id;
  if (lifeId === undefined) {
    return;
  }
  const requestGeneration = ++screenVisionStatusRequestGeneration;
  try {
    const status = await mainScreenVisionDeliveryService.getStatus();
    if (
      !isRuntimeActive(runtimeEpoch) ||
      requestGeneration !== screenVisionStatusRequestGeneration ||
      lifeIdentity.value?.id !== lifeId
    ) {
      return;
    }
    reconcileScreenVisionStatus(status);
  } catch (error: unknown) {
    if (
      !isRuntimeActive(runtimeEpoch) ||
      requestGeneration !== screenVisionStatusRequestGeneration ||
      lifeIdentity.value?.id !== lifeId
    ) {
      return;
    }
    const boundedError = screenVisionDeliveryErrorFromUnknown(error);
    if (
      screenVisionError.value?.code !==
      SCREEN_VISION_TERMINAL_SETTLEMENT_ERROR_CODE
    ) {
      screenVisionError.value = boundedError;
    }
  }
}

async function prepareScreenVisionReview(): Promise<void> {
  const lifeId = lifeIdentity.value?.id;
  if (lifeId === undefined || !screenVisionCanPrepare.value) {
    return;
  }

  const runtimeEpoch = lifecycleEpoch;
  const requestGeneration = ++screenVisionRequestGeneration;
  screenVisionPreparing.value = true;
  screenVisionError.value = undefined;
  try {
    const review = await mainScreenVisionDeliveryService.prepareReview();
    if (isCurrentScreenVisionRequest(runtimeEpoch, lifeId, requestGeneration)) {
      // Keep the prepared review locally for the display transition; the
      // authoritative backend status reread in finally reconciles it.
      screenVisionReview.value = review;
      screenVisionResult.value = undefined;
      screenVisionAttempt.value = undefined;
    }
  } catch (error: unknown) {
    if (isCurrentScreenVisionRequest(runtimeEpoch, lifeId, requestGeneration)) {
      screenVisionError.value = screenVisionDeliveryErrorFromUnknown(error);
    }
  } finally {
    if (isCurrentScreenVisionRequest(runtimeEpoch, lifeId, requestGeneration)) {
      screenVisionPreparing.value = false;
      void refreshScreenVisionStatus(runtimeEpoch);
    }
  }
}

async function executeScreenVisionReview(): Promise<void> {
  const lifeId = lifeIdentity.value?.id;
  const review = screenVisionReview.value;
  if (lifeId === undefined || review === undefined || !screenVisionCanSend.value) {
    return;
  }

  let attempt = screenVisionAttempt.value;
  if (attempt === undefined) {
    try {
      // New explicit confirmation: bind the attempt exactly to the backend
      // review so a retry can never be reused for another review.
      attempt = {
        reviewId: review.reviewId,
        confirmationEventId: createSecureVisionAttemptId(),
        deliveryId: createSecureVisionAttemptId(),
      };
    } catch {
      screenVisionError.value = {
        code: "VISION_IDENTITY_UNAVAILABLE",
        message: "A secure Vision attempt could not be created.",
        recoverable: true,
      };
      return;
    }
    screenVisionAttempt.value = attempt;
  }

  const runtimeEpoch = lifecycleEpoch;
  const requestGeneration = ++screenVisionRequestGeneration;
  screenVisionSending.value = true;
  screenVisionError.value = undefined;
  try {
    const result = await mainScreenVisionDeliveryService.executeReview(
      attempt.reviewId,
      attempt.confirmationEventId,
      attempt.deliveryId,
    );
    if (isCurrentScreenVisionRequest(runtimeEpoch, lifeId, requestGeneration)) {
      screenVisionResult.value = result;
      screenVisionError.value = undefined;
      // Lifecycle state is not fabricated here: the authoritative backend
      // status reread in finally reconciles review/attempt/status.
    }
  } catch (error: unknown) {
    if (isCurrentScreenVisionRequest(runtimeEpoch, lifeId, requestGeneration)) {
      // Preserve the bounded diagnostic for display.  The review and attempt
      // are deliberately NOT cleared: only the authoritative backend status
      // reread (reconcileScreenVisionStatus) may decide tuple retention.
      screenVisionError.value = screenVisionDeliveryErrorFromUnknown(error);
    }
  } finally {
    if (isCurrentScreenVisionRequest(runtimeEpoch, lifeId, requestGeneration)) {
      screenVisionSending.value = false;
      void refreshScreenVisionStatus(runtimeEpoch);
    }
  }
}

async function useScreenVisionAnalysisInChat(): Promise<void> {
  const lifeId = lifeIdentity.value?.id;
  const visionResultId = screenVisionResult.value?.visionResultId;
  if (
    lifeId === undefined ||
    visionResultId === undefined ||
    visionResultId === null ||
    !screenVisionCanUseInChat.value
  ) {
    return;
  }

  const runtimeEpoch = lifecycleEpoch;
  const requestGeneration = ++screenVisionRequestGeneration;
  screenVisionOffering.value = true;
  screenVisionError.value = undefined;
  try {
    await mainScreenVisionDeliveryService.offerVisionResultToChat(visionResultId);
    if (isCurrentScreenVisionRequest(runtimeEpoch, lifeId, requestGeneration)) {
      // The backend emitted the existing presentation-only attachment hint;
      // opening Chat is the only UI transition here. No Vision request is
      // performed by this explicit second-consent action.
      await openChat();
    }
  } catch (error: unknown) {
    if (isCurrentScreenVisionRequest(runtimeEpoch, lifeId, requestGeneration)) {
      screenVisionError.value = screenVisionDeliveryErrorFromUnknown(error);
    }
  } finally {
    if (isCurrentScreenVisionRequest(runtimeEpoch, lifeId, requestGeneration)) {
      screenVisionOffering.value = false;
    }
  }
}

async function abandonScreenVisionDelivery(): Promise<void> {
  const lifeId = lifeIdentity.value?.id;
  const review = screenVisionReview.value;
  if (lifeId === undefined || review === undefined || !screenVisionCanAbandon.value) {
    return;
  }

  const runtimeEpoch = lifecycleEpoch;
  const requestGeneration = ++screenVisionRequestGeneration;
  screenVisionAbandoning.value = true;
  screenVisionError.value = undefined;
  try {
    await mainScreenVisionDeliveryService.abandonDelivery(review.reviewId);
    if (isCurrentScreenVisionRequest(runtimeEpoch, lifeId, requestGeneration)) {
      // The abandon succeeded; the backend is idle.  Clear local state and let
      // the authoritative reread in finally confirm it.
      screenVisionReview.value = undefined;
      screenVisionAttempt.value = undefined;
      screenVisionStatus.value = { status: "idle", review: null };
    }
  } catch (error: unknown) {
    if (isCurrentScreenVisionRequest(runtimeEpoch, lifeId, requestGeneration)) {
      screenVisionError.value = screenVisionDeliveryErrorFromUnknown(error);
    }
  } finally {
    if (isCurrentScreenVisionRequest(runtimeEpoch, lifeId, requestGeneration)) {
      screenVisionAbandoning.value = false;
      void refreshScreenVisionStatus(runtimeEpoch);
    }
  }
}

function invalidateScreenObservationRequest(): void {
  screenObservationRequestGeneration += 1;
  screenObservationLoading.value = false;
  clearScreenObservation();
}

async function refreshScreenPerceptionStatus(
  lifeId: string,
  runtimeEpoch: number,
): Promise<void> {
  const requestGeneration = ++screenStatusRequestGeneration;
  try {
    const status = await mainScreenObservationService.getStatus(lifeId);
    if (
      !isRuntimeActive(runtimeEpoch) ||
      requestGeneration !== screenStatusRequestGeneration ||
      lifeIdentity.value?.id !== lifeId
    ) {
      return;
    }
    screenPerceptionStatus.value = status;
    if (!status.consentEnabled || !status.sessionArmed) {
      invalidateScreenObservationRequest();
    }
  } catch (error: unknown) {
    if (
      !isRuntimeActive(runtimeEpoch) ||
      requestGeneration !== screenStatusRequestGeneration ||
      lifeIdentity.value?.id !== lifeId
    ) {
      return;
    }
    invalidateScreenObservationRequest();
    screenPerceptionStatus.value = undefined;
    screenObservationError.value = screenObservationErrorFromUnknown(error);
  }
}

function applyCurrentLife(life: LifeIdentity, runtimeEpoch: number): void {
  if (!isRuntimeActive(runtimeEpoch)) {
    return;
  }
  const previousLifeId = lifeIdentity.value?.id;
  lifeIdentity.value = life;
  if (previousLifeId !== life.id) {
    screenStatusRequestGeneration += 1;
    invalidateScreenObservationRequest();
    screenPerceptionStatus.value = undefined;
    invalidateScreenVision();
  }
  void refreshScreenPerceptionStatus(life.id, runtimeEpoch);
  void refreshScreenVisionStatus(runtimeEpoch);
}

async function observeScreenNow(): Promise<void> {
  const lifeId = lifeIdentity.value?.id;
  if (lifeId === undefined || !canObserveScreen.value || screenObservationLoading.value) {
    return;
  }

  const runtimeEpoch = lifecycleEpoch;
  const requestGeneration = ++screenObservationRequestGeneration;
  clearScreenObservation();
  screenObservationLoading.value = true;
  screenObservationError.value = undefined;
  try {
    const observation = await mainScreenObservationService.observeNow(lifeId);
    if (
      isRuntimeActive(runtimeEpoch) &&
      lifeIdentity.value?.id === lifeId &&
      screenObservationRequestGeneration === requestGeneration
    ) {
      screenObservation.value = observation;
    }
  } catch (error: unknown) {
    if (
      isRuntimeActive(runtimeEpoch) &&
      lifeIdentity.value?.id === lifeId &&
      screenObservationRequestGeneration === requestGeneration
    ) {
      screenObservation.value = undefined;
      screenObservationError.value = screenObservationErrorFromUnknown(error);
    }
  } finally {
    if (
      isRuntimeActive(runtimeEpoch) &&
      lifeIdentity.value?.id === lifeId &&
      screenObservationRequestGeneration === requestGeneration
    ) {
      screenObservationLoading.value = false;
      void refreshScreenPerceptionStatus(lifeId, runtimeEpoch);
    }
  }
}

function isCurrentScreenPrepare(
  runtimeEpoch: number,
  lifeId: string,
  observationRequestGeneration: number,
  candidateId: string,
  handoffRequestGeneration: number,
): boolean {
  const observation = screenObservation.value;
  return (
    isRuntimeActive(runtimeEpoch) &&
    lifeIdentity.value?.id === lifeId &&
    screenObservationRequestGeneration === observationRequestGeneration &&
    screenHandoffRequestGeneration === handoffRequestGeneration &&
    observation?.status === "recognized" &&
    observation.candidateId === candidateId
  );
}

function prepareFailureInvalidatesScreenObservation(code: string): boolean {
  return new Set([
    "SCREEN_CONTEXT_LIFE_UNAVAILABLE",
    "SCREEN_CONTEXT_LIFE_CHANGED",
    "SCREEN_CONTEXT_SESSION_UNAVAILABLE",
    "SCREEN_CONTEXT_SESSION_CHANGED",
    "SCREEN_CONTEXT_CONSENT_UNAVAILABLE",
    "SCREEN_CONTEXT_CONSENT_DISABLED",
    "SCREEN_CONTEXT_UNAVAILABLE",
    "SCREEN_CONTEXT_EXPIRED",
    "SCREEN_CONTEXT_NO_USABLE",
  ]).has(code);
}

async function retryScreenContextGrantCleanup(): Promise<void> {
  const lifeId = screenContextGrantLifeId.value;
  const grant = screenContextGrant.value;
  const observation = screenObservation.value;
  if (
    lifeId === undefined ||
    grant === undefined ||
    observation?.status !== "recognized" ||
    screenPreparedCandidateId.value !== observation.candidateId ||
    screenContextAttachmentId.value !== undefined ||
    screenContextPreparing.value
  ) {
    return;
  }

  const runtimeEpoch = lifecycleEpoch;
  const observationRequestGeneration = screenObservationRequestGeneration;
  const handoffRequestGeneration = screenHandoffRequestGeneration;
  screenContextPreparing.value = true;

  try {
    await mainScreenObservationService.revokeMainPendingScreenContextGrant(
      lifeId,
      grant.grantId,
    );
    if (
      isCurrentScreenPrepare(
        runtimeEpoch,
        lifeId,
        observationRequestGeneration,
        observation.candidateId,
        handoffRequestGeneration,
      )
    ) {
      clearLocalPendingGrant(lifeId, grant.grantId);
      screenObservationError.value = undefined;
    }
  } catch (error: unknown) {
    if (
      isCurrentScreenPrepare(
        runtimeEpoch,
        lifeId,
        observationRequestGeneration,
        observation.candidateId,
        handoffRequestGeneration,
      )
    ) {
      screenObservationError.value = screenObservationErrorFromUnknown(error);
    }
  } finally {
    if (
      isCurrentScreenPrepare(
        runtimeEpoch,
        lifeId,
        observationRequestGeneration,
        observation.candidateId,
        handoffRequestGeneration,
      )
    ) {
      screenContextPreparing.value = false;
    }
  }
}

async function prepareScreenContextForChat(): Promise<void> {
  const lifeId = lifeIdentity.value?.id;
  const observation = screenObservation.value;
  if (
    lifeId === undefined ||
    observation?.status !== "recognized" ||
    !canUseScreenContextAction.value
  ) {
    return;
  }

  if (screenContextCleanupRequired.value) {
    await retryScreenContextGrantCleanup();
    return;
  }

  const runtimeEpoch = lifecycleEpoch;
  const observationRequestGeneration = screenObservationRequestGeneration;
  const candidateId = observation.candidateId;
  const handoffRequestGeneration = ++screenHandoffRequestGeneration;
  screenContextPreparing.value = true;
  screenObservationError.value = undefined;

  try {
    const grant = await mainScreenObservationService.prepareMainScreenContextForChat(
      lifeId,
      candidateId,
    );
    if (
      isCurrentScreenPrepare(
        runtimeEpoch,
        lifeId,
        observationRequestGeneration,
        candidateId,
        handoffRequestGeneration,
      )
    ) {
      screenContextGrant.value = grant;
      screenContextGrantLifeId.value = lifeId;
      screenPreparedCandidateId.value = candidateId;

      try {
        const attachment = await mainScreenObservationService.offerMainScreenContextToChat(
          lifeId,
          grant.grantId,
        );
        if (
          !isCurrentScreenPrepare(
            runtimeEpoch,
            lifeId,
            observationRequestGeneration,
            candidateId,
            handoffRequestGeneration,
          )
        ) {
          void mainScreenObservationService
            .revokeMainScreenContextAttachment(attachment.attachmentId)
            .catch(() => {
              // A stale offer is never displayed; backend exact cleanup owns
              // the late attachment even when the cleanup call is unavailable.
            });
          return;
        }

        screenContextGrant.value = undefined;
        screenContextGrantLifeId.value = undefined;
        screenContextAttachmentId.value = attachment.attachmentId;
      } catch (error: unknown) {
        if (
          !isCurrentScreenPrepare(
            runtimeEpoch,
            lifeId,
            observationRequestGeneration,
            candidateId,
            handoffRequestGeneration,
          )
        ) {
          revokePendingGrantWithoutPublishingError(lifeId, grant.grantId);
          return;
        }

        const boundedOfferError = screenObservationErrorFromUnknown(error);
        try {
          await mainScreenObservationService.revokeMainPendingScreenContextGrant(
            lifeId,
            grant.grantId,
          );
          if (
            isCurrentScreenPrepare(
              runtimeEpoch,
              lifeId,
              observationRequestGeneration,
              candidateId,
              handoffRequestGeneration,
            )
          ) {
            clearLocalPendingGrant(lifeId, grant.grantId);
            screenObservationError.value = boundedOfferError;
          }
        } catch (cleanupError: unknown) {
          if (
            isCurrentScreenPrepare(
              runtimeEpoch,
              lifeId,
              observationRequestGeneration,
              candidateId,
              handoffRequestGeneration,
            )
          ) {
            // Keep the opaque local Grant only as a bounded retry/cleanup
            // handle; it is never rendered or persisted.
            screenObservationError.value = screenObservationErrorFromUnknown(cleanupError);
          }
        }
      }
    } else {
      revokePendingGrantWithoutPublishingError(lifeId, grant.grantId);
    }
  } catch (error: unknown) {
    if (
      isCurrentScreenPrepare(
        runtimeEpoch,
        lifeId,
        observationRequestGeneration,
        candidateId,
        handoffRequestGeneration,
      )
    ) {
      const boundedError = screenObservationErrorFromUnknown(error);
      if (prepareFailureInvalidatesScreenObservation(boundedError.code)) {
        invalidateScreenObservationRequest();
        screenObservationError.value = boundedError;
      } else {
        screenObservationError.value = boundedError;
      }
    }
  } finally {
    if (
      isCurrentScreenPrepare(
        runtimeEpoch,
        lifeId,
        observationRequestGeneration,
        candidateId,
        handoffRequestGeneration,
      )
    ) {
      screenContextPreparing.value = false;
    }
  }
}

function handleMainWindowFocus(): void {
  const lifeId = lifeIdentity.value?.id;
  if (lifeId !== undefined) {
    void refreshScreenPerceptionStatus(lifeId, lifecycleEpoch);
    void refreshScreenVisionStatus(lifecycleEpoch);
  }
}

onMounted(async () => {
  const runtimeEpoch = ++lifecycleEpoch;
  window.addEventListener("focus", handleMainWindowFocus);

  // Capture the mounted host before any asynchronous storage / Life work.
  // The captured element is used only after the same lifecycle epoch is
  // still active, so a late Life continuation cannot reuse a stale host.
  const hostElement = bodyRendererElement.value;

  const runtimeBinding = new BodyRuntimeBindingController({
    loadRegistrySnapshot: () => bodyPackageService.getRegistrySnapshot(),
    installRegistrySnapshot: installManagedBodyPackageRegistrySnapshot,
    loadCurrentLife: () => storageService.getCurrentLife(),
    // App owns only the opaque bodyId composition entrypoint. Package
    // definitions and managed source values stay inside the body authority.
    createPresentation: (bodyId) => createBodyPresentationForBodyId(bodyId),
    getCurrentState: () => bodyStateMachine.getState(),
    onSnapshot: (snapshot) => {
      if (isRuntimeActive(runtimeEpoch)) {
        bodyState.value = snapshot.state;
      }
    },
  });
  bodyRuntimeBinding = runtimeBinding;

  // D17-C-F1 ordering is retained: the BodyStateMachine subscription is
  // installed before the expression listener and before any initial render.
  // Before the current Life is bound, transitions remain authoritative in the
  // machine and are intentionally presentation no-ops.
  unsubscribe = bodyStateMachine.subscribe(({ current }) => {
    if (!isRuntimeActive(runtimeEpoch)) {
      return;
    }
    void runtimeBinding.render(current);
  });

  // Expression-listener registration starts BEFORE the long main
  // initialization sequence (storage, Life, persona, provider), so chat
  // expressions are not needlessly lost during startup.
  bodyExpressionListener.start(({ state }) => {
    bodyStateMachine.transition(state);
  });

  // This event is only a post-commit refresh hint. Main rereads the
  // authoritative registry and Life and never accepts a bodyId or URL from
  // the event payload.
  bodyBindingChangedListener.start((event) => {
    if (!isRuntimeActive(runtimeEpoch) || event.version !== 1) {
      return;
    }
    void runtimeBinding
      .refresh()
      .then((life) => {
        if (isRuntimeActive(runtimeEpoch) && life !== undefined) {
          applyCurrentLife(life, runtimeEpoch);
        }
      })
      .catch(() => {
        // Refresh failure is presentation-only; a later hint retries.
      });
  });

  await storageService.initialize();
  if (!isRuntimeActive(runtimeEpoch)) {
    return;
  }

  const life = await runtimeBinding.initialize(hostElement, () =>
    initializeDefaultLife(),
  );
  if (!isRuntimeActive(runtimeEpoch)) {
    return;
  }
  if (life === undefined) {
    return;
  }
  applyCurrentLife(life, runtimeEpoch);

  const persona = await personaManager.getById(life.personaId);
  if (isRuntimeActive(runtimeEpoch) && bodyRuntimeBinding === runtimeBinding) {
    personaTemplate.value = persona;
  }
});

function isRuntimeActive(epoch: number): boolean {
  return lifecycleEpoch === epoch;
}

onUnmounted(() => {
  // Retire the epoch before touching any async owner so late provider, Life,
  // mount, and render continuations cannot apply or create new presentation
  // state after unmount.
  lifecycleEpoch += 1;
  screenStatusRequestGeneration += 1;
  screenVisionRequestGeneration += 1;
  screenVisionStatusRequestGeneration += 1;
  invalidateScreenObservationRequest();
  window.removeEventListener("focus", handleMainWindowFocus);
  unsubscribe?.();
  unsubscribe = undefined;
  bodyExpressionListener.stop();
  bodyBindingChangedListener.stop();
  bodyRuntimeBinding?.dispose();
  bodyRuntimeBinding = undefined;
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
      <section
        class="screen-perception"
        aria-label="Screen perception"
        data-testid="main-screen-perception"
      >
        <div class="screen-perception-header">
          <strong data-testid="screen-perception-indicator">
            Screen perception: {{ screenReadinessLabel }}
          </strong>
          <button
            type="button"
            data-testid="screen-observe-now"
            :disabled="!canObserveScreen"
            :aria-busy="screenObservationLoading"
            @click="observeScreenNow"
          >
            {{ screenObservationLoading ? "Observing…" : "Observe Now" }}
          </button>
        </div>
        <pre
          v-if="screenObservation?.status === 'recognized'"
          class="screen-observation-preview"
          data-testid="screen-observation-preview"
          aria-live="polite"
        >{{ screenObservation.text }}</pre>
        <p
          v-else-if="screenObservation?.status === 'noText'"
          class="screen-observation-no-text"
          data-testid="screen-observation-no-text"
          aria-live="polite"
        >No screen text was recognized.</p>
        <button
          v-if="screenObservation?.status === 'recognized'"
          type="button"
          class="screen-use-in-chat"
          data-testid="screen-use-in-chat"
          :disabled="!canUseScreenContextAction"
          :aria-busy="screenContextPreparing"
          @click="prepareScreenContextForChat"
        >
          {{
            screenContextPreparing
              ? "Transferring…"
              : screenObservationPrepared
                ? "Ready in chat"
                : screenContextCleanupRequired
                  ? "Retry cleanup"
                  : "Use in chat"
          }}
        </button>
        <p
          v-if="screenObservationError"
          class="screen-perception-error"
          data-testid="screen-observation-error"
        >
          {{ screenObservationError.message }}
        </p>
      </section>
      <section
        class="screen-vision-delivery"
        aria-label="Screen Vision delivery"
        data-testid="main-screen-vision-delivery"
      >
        <div class="screen-vision-header">
          <strong>Screen Vision</strong>
          <button
            type="button"
            data-testid="screen-vision-prepare"
            :disabled="!screenVisionCanPrepare"
            :aria-busy="screenVisionPreparing"
            @click="prepareScreenVisionReview"
          >
            {{
              screenVisionPreparing
                ? "Preparing…"
                : "Prepare the full selected screen target for Vision"
            }}
          </button>
        </div>
        <div
          v-if="screenVisionReviewForDisplay"
          class="screen-vision-review"
          data-testid="screen-vision-review"
        >
          <p>
            One screen image from the full selected target will be sent to
            {{ screenVisionReviewForDisplay.providerHost }} using
            {{ screenVisionReviewForDisplay.modelName }}.
          </p>
          <p v-if="screenVisionDefiniteDeliveryObserved">
            The Vision provider received this image, but local one-shot finalization could not be completed. This attempt will not be resent automatically.
          </p>
          <p v-else>The image has not been sent yet.</p>
          <p>Screen contents are treated as untrusted data by the Vision prompt.</p>
          <p>No additional manual privacy masks are applied in this V1 full-target analysis.</p>
          <p class="screen-vision-review-meta">
            {{ screenVisionReviewForDisplay.profileDisplayName }} ·
            {{ screenVisionReviewForDisplay.width }} ×
            {{ screenVisionReviewForDisplay.height }}
          </p>
          <button
            v-if="screenVisionReview && !screenVisionDefiniteDeliveryObserved"
            type="button"
            class="screen-vision-send"
            data-testid="screen-vision-analyze"
            :disabled="!screenVisionCanSend"
            :aria-busy="screenVisionSending"
            @click="executeScreenVisionReview"
          >
            {{
              screenVisionSending
                ? "Analyzing…"
                : screenVisionRetryAvailable
                  ? "Retry this same Vision attempt"
                  : "Analyze with Vision now"
            }}
          </button>
          <button
            v-if="screenVisionCanAbandon"
            type="button"
            class="screen-vision-abandon"
            data-testid="screen-vision-abandon"
            :disabled="screenVisionAbandoning"
            :aria-busy="screenVisionAbandoning"
            @click="abandonScreenVisionDelivery"
          >
            {{ screenVisionAbandoning ? "Abandoning…" : "Abandon this Vision attempt" }}
          </button>
        </div>
        <p
          v-if="screenVisionError"
          class="screen-vision-error"
          data-testid="screen-vision-error"
          aria-live="polite"
        >
          {{ screenVisionError.message }}
        </p>
        <section
          v-if="screenVisionResult"
          class="screen-vision-result"
          data-testid="screen-vision-result"
          aria-live="polite"
        >
          <strong>Vision analysis</strong>
          <p>AI-generated interpretation. Screen contents may be incomplete or misread.</p>
          <p>{{ screenVisionResult.summary }}</p>
          <ul>
            <li v-for="observation in screenVisionResult.observations" :key="observation">
              {{ observation }}
            </li>
          </ul>
          <div class="screen-vision-chat-handoff">
            <template v-if="screenVisionResult.visionResultId !== null">
              <p>This attaches the AI-generated screen interpretation to your next Chat message.</p>
              <p>The screenshot itself will not be attached.</p>
            </template>
            <p v-else>Chat handoff is unavailable for this analysis. Prepare a new analysis.</p>
            <button
              type="button"
              data-testid="screen-vision-use-in-chat"
              :disabled="!screenVisionCanUseInChat"
              :aria-busy="screenVisionOffering"
              @click="useScreenVisionAnalysisInChat"
            >
              {{
                screenVisionResult.visionResultId === null
                  ? "Vision analysis unavailable in chat"
                  : screenVisionOffering
                    ? "Attaching…"
                    : "Use Vision analysis in chat"
              }}
            </button>
          </div>
        </section>
      </section>
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

.body-renderer-host {
  width: min(72vw, 300px);
  height: min(64vh, 420px);
  min-width: 1px;
  min-height: 1px;
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

.screen-perception {
  display: grid;
  width: min(100%, 320px);
  gap: 0.4rem;
  padding: 0.6rem;
  border: 1px solid rgb(255 255 255 / 18%);
  border-radius: 0.7rem;
  background: rgb(15 23 42 / 66%);
  user-select: text;
}

.screen-perception-header {
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 0.5rem;
  align-items: center;
}

.screen-perception-header strong {
  color: #d9faff;
  font-size: 0.82rem;
  font-weight: 600;
}

.screen-perception-header button {
  border: 1px solid rgb(125 211 252 / 45%);
  border-radius: 0.45rem;
  padding: 0.3rem 0.55rem;
  background: rgb(14 116 144 / 80%);
  color: #f0fdfa;
  cursor: pointer;
  font-size: 0.78rem;
}

.screen-perception-header button:disabled {
  background: rgb(71 85 105 / 65%);
  color: #cbd5e1;
  cursor: not-allowed;
}

.screen-perception-header button:not(:disabled):hover,
.screen-perception-header button:not(:disabled):focus-visible {
  background: rgb(8 145 178 / 90%);
}

.screen-observation-preview {
  max-height: 8rem;
  margin: 0;
  overflow: auto;
  border-radius: 0.4rem;
  padding: 0.45rem;
  background: rgb(2 6 23 / 72%);
  color: #e2e8f0;
  font: 0.75rem/1.35 ui-monospace, SFMono-Regular, Consolas, monospace;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.screen-observation-no-text {
  margin: 0;
  color: #cbd5e1;
  font-size: 0.78rem;
}

.screen-use-in-chat {
  justify-self: start;
  border: 1px solid rgb(167 243 208 / 46%);
  border-radius: 0.45rem;
  padding: 0.3rem 0.55rem;
  background: rgb(6 95 70 / 82%);
  color: #ecfdf5;
  cursor: pointer;
  font-size: 0.78rem;
}

.screen-use-in-chat:disabled {
  background: rgb(71 85 105 / 65%);
  color: #cbd5e1;
  cursor: not-allowed;
}

.screen-use-in-chat:not(:disabled):hover,
.screen-use-in-chat:not(:disabled):focus-visible {
  background: rgb(5 150 105 / 90%);
}

.screen-perception-error {
  margin: 0;
  color: #fecaca;
  font-size: 0.78rem;
}

.screen-vision-delivery {
  display: grid;
  width: min(100%, 320px);
  gap: 0.4rem;
  padding: 0.6rem;
  border: 1px solid rgb(251 191 36 / 30%);
  border-radius: 0.7rem;
  background: rgb(69 26 3 / 58%);
  user-select: text;
}

.screen-vision-header {
  display: grid;
  gap: 0.4rem;
}

.screen-vision-header strong {
  color: #fef3c7;
  font-size: 0.82rem;
  font-weight: 600;
}

.screen-vision-header button,
.screen-vision-send,
.screen-vision-abandon {
  border: 1px solid rgb(253 230 138 / 45%);
  border-radius: 0.45rem;
  padding: 0.35rem 0.55rem;
  background: rgb(180 83 9 / 82%);
  color: #fffbeb;
  cursor: pointer;
  font-size: 0.78rem;
  text-align: left;
}

.screen-vision-header button:disabled,
.screen-vision-send:disabled,
.screen-vision-abandon:disabled {
  background: rgb(71 85 105 / 65%);
  color: #cbd5e1;
  cursor: not-allowed;
}

.screen-vision-header button:not(:disabled):hover,
.screen-vision-header button:not(:disabled):focus-visible,
.screen-vision-send:not(:disabled):hover,
.screen-vision-send:not(:disabled):focus-visible {
  background: rgb(217 119 6 / 92%);
}

.screen-vision-review {
  display: grid;
  gap: 0.25rem;
  border-top: 1px solid rgb(253 230 138 / 20%);
  padding-top: 0.35rem;
}

.screen-vision-review p,
.screen-vision-result p {
  margin: 0;
  color: #fef3c7;
  font-size: 0.76rem;
  line-height: 1.35;
}

.screen-vision-review-meta {
  color: #fde68a !important;
}

.screen-vision-send {
  margin-top: 0.15rem;
  background: rgb(146 64 14 / 90%);
  font-weight: 600;
}

.screen-vision-abandon {
  justify-self: start;
  border-color: rgb(254 202 202 / 35%);
  background: rgb(127 29 29 / 78%);
}

.screen-vision-abandon:not(:disabled):hover,
.screen-vision-abandon:not(:disabled):focus-visible {
  background: rgb(185 28 28 / 88%);
}

.screen-vision-error {
  margin: 0;
  color: #fecaca;
  font-size: 0.78rem;
  line-height: 1.35;
}

.screen-vision-result {
  display: grid;
  gap: 0.25rem;
  border-top: 1px solid rgb(253 230 138 / 20%);
  padding-top: 0.35rem;
}

.screen-vision-result strong {
  color: #fef3c7;
  font-size: 0.82rem;
}

.screen-vision-result ul {
  display: grid;
  gap: 0.2rem;
  margin: 0;
  padding-left: 1rem;
  color: #fef3c7;
  font-size: 0.76rem;
}

</style>
