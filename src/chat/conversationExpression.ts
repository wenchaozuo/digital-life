//! D17-B2 truthful conversation lifecycle → desktop body expression.
//!
//! The conversation runtime, its persistence, its turn outcomes, and its
//! errors remain authoritative.  This module only projects a bounded,
//! best-effort presentation signal onto the main desktop body through the
//! frozen B1 bridge (`bodyExpressionBridge`).
//!
//! Principles:
//! - No timer, no fake playback, no `speaking` synthesis: the coordinator can
//!   only emit thinking / waiting / idle / error.  `speaking` is compatible
//!   with the frozen five-state enum but is never produced automatically.
//! - Operation generation is in-memory and monotonically increasing; stale
//!   completions are ignored.  No persistence, no `Date.now` identity, no
//!   UUID, and no generation in the cross-window payload.
//! - Delivery is serialized on a promise tail so `thinking → idle` and
//!   `waiting → error` can never reorder.
//! - A failed publication is contained here and never poisons the queue:
//!   conversation success/cancellation/errors are never affected by
//!   expression transport failures.

import { bodyExpressionBridge } from "../body/expressionBridge.ts";
import type { BodyState } from "../body/types.ts";

/** The four body states the truthful conversation lifecycle may produce. */
export type ConversationExpressionState = Extract<
  BodyState,
  "idle" | "thinking" | "waiting" | "error"
>;

export type ConversationExpressionPublisher = (state: BodyState) => Promise<void>;

const defaultPublisher: ConversationExpressionPublisher = (state) =>
  bodyExpressionBridge.publishBodyExpression(state);

export class ConversationExpressionCoordinator {
  private readonly publisher: ConversationExpressionPublisher;
  private generation = 0;
  private deliveryTail: Promise<void> = Promise.resolve();

  constructor(publisher: ConversationExpressionPublisher = defaultPublisher) {
    this.publisher = publisher;
  }

  /**
   * Begins a new conversation operation: bumps the generation, returns the
   * operation token, and enqueues the begin state for presentation.
   */
  begin(state: ConversationExpressionState): number {
    this.generation += 1;
    const token = this.generation;
    this.enqueue(state);
    return token;
  }

  /**
   * Completes the operation identified by `token`.  A token from an older
   * generation is stale and ignored, so a late completion can never
   * overwrite the presentation owned by the current operation.
   */
  complete(token: number, state: ConversationExpressionState): void {
    if (token !== this.generation) {
      return;
    }
    this.enqueue(state);
  }

  private enqueue(state: ConversationExpressionState): void {
    this.deliveryTail = this.deliveryTail
      .then(() => this.publisher(state))
      .catch(() => {
        // Transport failure is contained inside the presentation layer.  The
        // swallowed rejection also keeps the tail resolved so the next
        // expression transition is still attempted.
      });
  }
}

/** Module singleton used by ChatView; tests construct their own instance. */
export const conversationExpression = new ConversationExpressionCoordinator();