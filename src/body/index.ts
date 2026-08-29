import { BodyRenderCoordinator } from "./bodyRenderCoordinator.ts";
import { BodyStateMachine } from "./bodyStateMachine.ts";
import { FallbackBodyProvider } from "./fallbackBodyProvider.ts";
import { PngBodyProvider } from "./pngBodyProvider.ts";
import { PngBodyRenderer } from "./pngBodyRenderer.ts";
import { FallbackBodyRenderer } from "./fallbackBodyRenderer.ts";
import type { BodyRenderer } from "./bodyRenderer.ts";

export { BodyStateMachine } from "./bodyStateMachine.ts";
export { BodyRenderCoordinator } from "./bodyRenderCoordinator.ts";
export { FallbackBodyProvider } from "./fallbackBodyProvider.ts";
export type { BodyProvider, BodySnapshot, BodyState, BodyStateChange } from "./types.ts";
export { BODY_STATES } from "./types.ts";
export { PngBodyProvider } from "./pngBodyProvider.ts";
export type { PngBodyResources } from "./pngBodyResources.ts";
export { FallbackBodyRenderer } from "./fallbackBodyRenderer.ts";
export {
  DEFAULT_BODY_ID,
  createBodyPresentationForBodyId,
  resolveBodyBinding,
} from "./bodyBinding.ts";
export type {
  BodyPresentationComposition,
  BodyPresentationKind,
  ResolvedBodyBinding,
} from "./bodyBinding.ts";
export {
  BODY_EXPRESSION_EVENT_V1,
  BODY_EXPRESSION_SOURCE,
  BODY_EXPRESSION_TARGET,
  BODY_EXPRESSION_VERSION,
  BodyExpressionListenerLifecycle,
  bodyExpressionBridge,
  createBodyExpressionBridge,
  isBodyExpressionEventV1,
} from "./expressionBridge.ts";
export type { BodyRenderResult } from "./bodyRenderCoordinator.ts";
export { BodyRendererError, BodyRendererHost } from "./bodyRenderer.ts";
export type { BodyRenderer } from "./bodyRenderer.ts";
export { PngBodyRenderer } from "./pngBodyRenderer.ts";
export {
  BodyPackageService,
  bodyPackageService,
} from "./bodyPackageService.ts";
export type {
  BodyPackageAssetSnapshot,
  BodyPackageStatus,
  InstallLive2DBodyPackageRequest,
  InstalledBodyPackageSnapshot,
} from "./bodyPackageService.ts";
export {
  installManagedBodyPackageRegistrySnapshot,
} from "./bodyPackage.ts";
export {
  BodyRuntimeBindingController,
} from "./bodyRuntimeBinding.ts";
export type {
  BodyRuntimeBindingAuthority,
  BodyRuntimeBindingControllerOptions,
} from "./bodyRuntimeBinding.ts";
export {
  BODY_BINDING_CHANGED_EVENT,
  BODY_BINDING_CHANGED_VERSION,
  BodyBindingChangedListenerLifecycle,
  bodyBindingChangedBridge,
  createBodyBindingChangedBridge,
  isBodyBindingChangedEvent,
} from "./bodyBindingEvent.ts";
export type {
  BodyBindingChangedBridge,
  BodyBindingChangedEvent,
  BodyBindingChangedHandler,
  BodyBindingChangedTransport,
} from "./bodyBindingEvent.ts";
export function createDefaultBodyRenderer(): BodyRenderer {
  return new FallbackBodyRenderer(
    new PngBodyRenderer(),
    new PngBodyRenderer(),
  );
}
export type {
  BodyExpressionBridge,
  BodyExpressionEventV1,
  BodyExpressionHandler,
  BodyExpressionTransport,
} from "./expressionBridge.ts";

// D17-C production composition: a real PngBodyProvider is always the stable
// fallback.  A future Live2D provider can replace the primary without any
// App.vue ownership change.
export const defaultBodyProvider = new FallbackBodyProvider(
  new PngBodyProvider(),
  new PngBodyProvider(),
);
export const bodyRenderCoordinator = new BodyRenderCoordinator(defaultBodyProvider);
export const bodyStateMachine = new BodyStateMachine();
