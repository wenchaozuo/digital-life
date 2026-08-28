import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

import {
  BODY_EXPRESSION_SOURCE,
  BODY_EXPRESSION_TARGET,
  createBodyExpressionBridge,
  isBodyExpressionEventV1,
  type BodyExpressionEventV1,
  type BodyExpressionHandler,
  type BodyExpressionTransport,
} from "../src/body/expressionBridge.ts";
import { BodyStateMachine } from "../src/body/bodyStateMachine.ts";
import { BODY_STATES, type BodyState } from "../src/body/types.ts";

const validEvent = (state: BodyState): BodyExpressionEventV1 => ({
  version: 1,
  state,
  source: "conversation",
});

class FakeTransport implements BodyExpressionTransport {
  readonly published: Array<{ target: string; payload: BodyExpressionEventV1 }> = [];
  private activeHandler: ((payload: unknown) => void) | undefined;

  async publish(target: string, payload: BodyExpressionEventV1): Promise<void> {
    this.published.push({ target, payload });
  }

  async subscribe(handler: (payload: unknown) => void): Promise<() => void> {
    this.activeHandler = handler;
    return () => {
      this.activeHandler = undefined;
    };
  }

  emit(payload: unknown): void {
    this.activeHandler?.(payload);
  }
}

test("valid expression payloads are accepted for every body state", () => {
  for (const state of BODY_STATES) {
    assert.equal(isBodyExpressionEventV1(validEvent(state)), true, `state ${state}`);
  }
});

test("malformed payloads are rejected without throwing", () => {
  const malformed: unknown[] = [
    null,
    undefined,
    [1, 2, 3],
    "idle",
    42,
    true,
    {},
    { version: 2, state: "idle", source: "conversation" },
    { version: 1, state: "idle", source: "emotion" },
    { version: 1, state: "dancing", source: "conversation" },
    { version: 1, source: "conversation" },
    { version: 1, state: "idle" },
    { version: 1, state: "idle", source: "conversation", extra: "metadata" },
  ];
  for (const payload of malformed) {
    assert.equal(isBodyExpressionEventV1(payload), false, JSON.stringify(payload));
  }
});

test("exact plain-object validation accepts only plain payloads", () => {
  // Accepted: a normal object and a null-prototype plain object.
  assert.equal(isBodyExpressionEventV1(validEvent("idle")), true);
  const nullPrototype = Object.assign(Object.create(null), {
    version: 1,
    state: "waiting",
    source: "conversation",
  });
  assert.equal(isBodyExpressionEventV1(nullPrototype), true);

  // Rejected without throwing: class instance, Date, Map, Set, array,
  // function, and any payload beyond the exact three keys.
  const nonPlain: unknown[] = [
    new (class FakeEvent {})() as object,
    new Date("2026-01-01T00:00:00.000Z"),
    new Map<string, unknown>(),
    new Set<unknown>(),
    [1, 2, 3],
    () => ({ version: 1, state: "idle", source: "conversation" }),
  ];
  for (const payload of nonPlain) {
    assert.equal(isBodyExpressionEventV1(payload), false, String(payload));
  }
});

test("publisher targets the main window only with the minimized payload", async () => {
  const transport = new FakeTransport();
  const bridge = createBodyExpressionBridge(transport);

  await bridge.publishBodyExpression("thinking");
  await bridge.publishBodyExpression("error");

  assert.equal(BODY_EXPRESSION_TARGET, "main");
  assert.equal(BODY_EXPRESSION_SOURCE, "conversation");
  assert.equal(transport.published.length, 2);
  for (const record of transport.published) {
    assert.equal(record.target, "main", "expressions must target main only");
    assert.deepEqual(Object.keys(record.payload).sort(), ["source", "state", "version"]);
  }
  assert.deepEqual(transport.published[0].payload, {
    version: 1,
    state: "thinking",
    source: "conversation",
  });
});

test("a valid expression event transitions the main body state machine", async () => {
  const transport = new FakeTransport();
  const bridge = createBodyExpressionBridge(transport);
  const machine = new BodyStateMachine();
  await bridge.listenForBodyExpression(({ state }) => machine.transition(state));

  transport.emit(validEvent("thinking"));
  assert.equal(machine.getState(), "thinking");
  transport.emit(validEvent("idle"));
  assert.equal(machine.getState(), "idle");
});

test("malformed events never transition and never throw", async () => {
  const transport = new FakeTransport();
  const bridge = createBodyExpressionBridge(transport);
  const machine = new BodyStateMachine();
  await bridge.listenForBodyExpression(({ state }) => machine.transition(state));

  transport.emit(null);
  transport.emit({ version: 9, state: "thinking", source: "conversation" });
  transport.emit({ version: 1, state: "dancing", source: "conversation" });
  transport.emit({ version: 1, state: "thinking", source: "system" });
  transport.emit("thinking");

  assert.equal(machine.getState(), "idle");
});

test("unsubscribe stops further transitions and leaks no listener", async () => {
  const transport = new FakeTransport();
  const bridge = createBodyExpressionBridge(transport);
  const machine = new BodyStateMachine();
  const unlisten = await bridge.listenForBodyExpression(({ state }) => {
    machine.transition(state);
  });

  transport.emit(validEvent("waiting"));
  assert.equal(machine.getState(), "waiting");

  unlisten();
  transport.emit(validEvent("thinking"));
  assert.equal(machine.getState(), "waiting", "no transition after unsubscribe");
});

test("main ownership shape: App.vue listens, ChatView stays unwired in B1", () => {
  const appSource = fs.readFileSync(new URL("../src/App.vue", import.meta.url), "utf8");
  assert.match(appSource, /bodyExpressionBridge/);
  assert.match(appSource, /listenForBodyExpression/);
  assert.match(appSource, /bodyStateMachine\.transition/);
  assert.doesNotMatch(
    appSource,
    /@tauri-apps\/api\/event/,
    "Tauri transport details must stay inside the expression bridge",
  );

  const chatSource = fs.readFileSync(new URL("../src/chat/ChatView.vue", import.meta.url), "utf8");
  assert.doesNotMatch(chatSource, /expressionBridge/, "ChatView is unchanged in B1");
  assert.doesNotMatch(chatSource, /listenForBodyExpression/);
  assert.doesNotMatch(chatSource, /publishBodyExpression/);
});

test("body state set is exactly the frozen five states", () => {
  assert.deepEqual([...BODY_STATES], ["idle", "thinking", "speaking", "waiting", "error"]);
});

// Type-level smoke: the handler receives a fully typed V1 event.
const handler: BodyExpressionHandler = (event) => {
  void event.version;
  void event.state;
  void event.source;
};
void handler;