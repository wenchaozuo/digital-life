import { emitTo, listen, type Event, type UnlistenFn } from "@tauri-apps/api/event";

import { BODY_STATES, type BodyState } from "./types.ts";

// D17-B1 cross-WebView desktop body expression transport.
//
// The desktop body lives only in the `main` WebView window and the main
// window stays the ONLY owner of the BodyStateMachine / body provider
// rendering state.  Other windows may publish ephemeral presentation
// evidence to the main window through this bounded bridge.
//
// This bridge is presentation-only.  It is NOT Life / Emotion / Relationship
// / Memory / Episode / Goal / Autonomy / Permission authority: nothing here
// persists, no SQLite row is written, and LifeIdentity is never touched.
// The versioned payload carries exactly `{ version, state, source }` and no
// arbitrary metadata.

export const BODY_EXPRESSION_EVENT_V1 = "digital-life://body-expression/v1";
export const BODY_EXPRESSION_VERSION = 1;
export const BODY_EXPRESSION_SOURCE = "conversation";
export const BODY_EXPRESSION_TARGET = "main";

export interface BodyExpressionEventV1 {
  version: 1;
  state: BodyState;
  source: "conversation";
}

export type BodyExpressionHandler = (event: BodyExpressionEventV1) => void;

/**
 * Runtime receiver-side validation.  The payload is never trusted merely
 * because TypeScript names a type.  It must be an exact plain object (its
 * prototype is `Object.prototype` or `null`) with exactly the three V1
 * fields, version 1, source "conversation", and a known body state.
 * Arrays, Date, Map/Set, class instances, and every other non-plain value
 * are rejected without throwing.
 */
export function isBodyExpressionEventV1(payload: unknown): payload is BodyExpressionEventV1 {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(payload);
  if (prototype !== Object.prototype && prototype !== null) {
    return false;
  }
  const candidate = payload as Record<string, unknown>;
  if (Object.keys(candidate).length !== 3) {
    return false;
  }
  if (candidate.version !== BODY_EXPRESSION_VERSION) {
    return false;
  }
  if (candidate.source !== BODY_EXPRESSION_SOURCE) {
    return false;
  }
  return (
    typeof candidate.state === "string" &&
    (BODY_STATES as readonly string[]).includes(candidate.state)
  );
}

/**
 * Minimal transport seam so tests never need a real Tauri desktop runtime.
 * The production adapter is backed by @tauri-apps/api/event (targeted
 * `emitTo` + `listen`); tests inject a fake transport.
 */
export interface BodyExpressionTransport {
  publish(target: string, payload: BodyExpressionEventV1): Promise<void>;
  subscribe(handler: (payload: unknown) => void): Promise<() => void>;
}

export interface BodyExpressionBridge {
  /** Publish one ephemeral expression state to the main body window. */
  publishBodyExpression(state: BodyState): Promise<void>;
  /** Receive expressions on the main side; the returned function unsubscribes. */
  listenForBodyExpression(handler: BodyExpressionHandler): Promise<() => void>;
}

export function createBodyExpressionBridge(
  transport: BodyExpressionTransport,
): BodyExpressionBridge {
  return {
    async publishBodyExpression(state) {
      await transport.publish(BODY_EXPRESSION_TARGET, {
        version: BODY_EXPRESSION_VERSION,
        state,
        source: BODY_EXPRESSION_SOURCE,
      });
    },
    async listenForBodyExpression(handler) {
      return transport.subscribe((payload: unknown) => {
        if (!isBodyExpressionEventV1(payload)) {
          // Malformed cross-window input is ignored, never thrown, and never
          // reaches the body state machine.
          return;
        }
        handler(payload);
      });
    },
  };
}

const tauriBodyExpressionTransport: BodyExpressionTransport = {
  async publish(target, payload) {
    await emitTo(target, BODY_EXPRESSION_EVENT_V1, payload);
  },
  async subscribe(handler) {
    const unlisten: UnlistenFn = await listen(
      BODY_EXPRESSION_EVENT_V1,
      (event: Event<unknown>) => handler(event.payload),
    );
    return unlisten;
  },
};

// Production singleton.  All Tauri transport details live inside this module;
// components consume only the narrow bridge API.
export const bodyExpressionBridge = createBodyExpressionBridge(tauriBodyExpressionTransport);

/**
 * D17-C main-side listener registration lifecycle.
 *
 * Registration is asynchronous, so this controller fences the mount/unmount
 * race: if the component unmounts while the registration promise is still
 * pending, the eventually-resolved `unlisten` function is invoked exactly
 * once and no registration leaks.  In the normal path `stop()` unlistens
 * exactly once; a second `stop()` is a no-op.
 */
export class BodyExpressionListenerLifecycle {
  private readonly register: (handler: BodyExpressionHandler) => Promise<() => void>;
  private active = true;
  private unlisten: (() => void) | undefined;

  constructor(register: (handler: BodyExpressionHandler) => Promise<() => void>) {
    this.register = register;
  }

  start(handler: BodyExpressionHandler): void {
    void this.register(handler).then(
      (unlisten) => {
        if (!this.active) {
          // The component unmounted while registration was pending: invoke
          // the resolved unlisten immediately and never store it.
          unlisten();
          return;
        }
        this.unlisten = unlisten;
      },
      () => {
        // Registration failure is contained: no listener exists to clean up.
      },
    );
  }

  stop(): void {
    this.active = false;
    const unlisten = this.unlisten;
    this.unlisten = undefined;
    unlisten?.();
  }
}