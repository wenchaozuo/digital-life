import { BodyStateMachine } from "./bodyStateMachine";
import { PngBodyProvider } from "./pngBodyProvider";

export { BodyStateMachine } from "./bodyStateMachine";
export type { BodyProvider, BodySnapshot, BodyState, BodyStateChange } from "./types";
export { BODY_STATES } from "./types";

// Future Live2D providers can implement the same BodyProvider contract.
export const defaultBodyProvider = new PngBodyProvider();
export const bodyStateMachine = new BodyStateMachine();
