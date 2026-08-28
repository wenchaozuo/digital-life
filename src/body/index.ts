import { BodyStateMachine } from "./bodyStateMachine.ts";
import { PngBodyProvider } from "./pngBodyProvider.ts";

export { BodyStateMachine } from "./bodyStateMachine.ts";
export type { BodyProvider, BodySnapshot, BodyState, BodyStateChange } from "./types.ts";
export { BODY_STATES } from "./types.ts";
export {
  BODY_EXPRESSION_EVENT_V1,
  BODY_EXPRESSION_SOURCE,
  BODY_EXPRESSION_TARGET,
  BODY_EXPRESSION_VERSION,
  bodyExpressionBridge,
  createBodyExpressionBridge,
  isBodyExpressionEventV1,
} from "./expressionBridge.ts";
export type {
  BodyExpressionBridge,
  BodyExpressionEventV1,
  BodyExpressionHandler,
  BodyExpressionTransport,
} from "./expressionBridge.ts";

// Future Live2D providers can implement the same BodyProvider contract.
export const defaultBodyProvider = new PngBodyProvider();
export const bodyStateMachine = new BodyStateMachine();