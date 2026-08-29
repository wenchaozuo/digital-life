export const BODY_BINDING_CHANGED_EVENT =
  "digital-life://body-binding-changed/v1";
export const BODY_BINDING_CHANGED_VERSION = 1;

/**
 * A post-commit refresh hint only. It deliberately contains no bodyId,
 * source path, URL, or package authority; Main rereads those from SQLite and
 * the managed registry.
 */
export interface BodyBindingChangedEvent {
  readonly version: 1;
  readonly lifeId: string;
  readonly lifeVersion: number;
}

export function isBodyBindingChangedEvent(
  value: unknown,
): value is BodyBindingChangedEvent {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    return false;
  }
  const candidate = value as Record<string, unknown>;
  return (
    Object.keys(candidate).length === 3 &&
    candidate.version === BODY_BINDING_CHANGED_VERSION &&
    typeof candidate.lifeId === "string" &&
    candidate.lifeId.length > 0 &&
    candidate.lifeId.length <= 128 &&
    typeof candidate.lifeVersion === "number" &&
    Number.isSafeInteger(candidate.lifeVersion) &&
    candidate.lifeVersion > 0
  );
}

export type BodyBindingChangedHandler = (event: BodyBindingChangedEvent) => void;

export interface BodyBindingChangedTransport {
  subscribe(handler: (payload: unknown) => void): Promise<() => void>;
}

export interface BodyBindingChangedBridge {
  listen(handler: BodyBindingChangedHandler): Promise<() => void>;
}

export function createBodyBindingChangedBridge(
  transport: BodyBindingChangedTransport,
): BodyBindingChangedBridge {
  return {
    async listen(handler) {
      return transport.subscribe((payload) => {
        if (isBodyBindingChangedEvent(payload)) {
          handler(payload);
        }
      });
    },
  };
}

const tauriBodyBindingChangedTransport: BodyBindingChangedTransport = {
  async subscribe(handler) {
    const unlisten: UnlistenFn = await listen(
      BODY_BINDING_CHANGED_EVENT,
      (event: Event<unknown>) => handler(event.payload),
    );
    return unlisten;
  },
};

export const bodyBindingChangedBridge = createBodyBindingChangedBridge(
  tauriBodyBindingChangedTransport,
);

/** Registration lifecycle fence for Main-WebView refresh hints. */
export class BodyBindingChangedListenerLifecycle {
  private readonly register: (
    handler: BodyBindingChangedHandler,
  ) => Promise<() => void>;
  private active = true;
  private unlisten: (() => void) | undefined;

  constructor(
    register: (
      handler: BodyBindingChangedHandler,
    ) => Promise<() => void>,
  ) {
    this.register = register;
  }

  start(handler: BodyBindingChangedHandler): void {
    void this.register(handler).then(
      (unlisten) => {
        if (!this.active) {
          unlisten();
          return;
        }
        this.unlisten = unlisten;
      },
      () => {
        // Registration failure is contained; the next startup rereads the
        // authoritative registry and Life state.
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
import { listen, type Event, type UnlistenFn } from "@tauri-apps/api/event";
