import {
  combineCognitionContexts,
  memoryContextBuilder,
} from "../memory/context/memoryContextBuilder.ts";
import type { MemoryContextResult } from "../memory/context/types.ts";
import type {
  MemoryRetrievalResult,
  RetrievalQuery,
} from "../memory/retrieval";

export const CONVERSATION_MEMORY_LIMIT = 5;

export interface ConversationMemoryWarning {
  code: "MEMORY_RETRIEVAL_UNAVAILABLE";
}

export interface MemoryRetrieverPort {
  retrieve(query: RetrievalQuery): Promise<readonly MemoryRetrievalResult[]>;
}

export interface ConversationMemoryPreparation {
  memoryContext: MemoryContextResult;
  warning?: ConversationMemoryWarning;
}

export async function prepareConversationMemoryContext(
  lifeId: string,
  queryText: string,
  retriever: MemoryRetrieverPort,
): Promise<ConversationMemoryPreparation> {
  try {
    const memories = await retriever.retrieve({
      lifeId,
      queryText,
      limit: CONVERSATION_MEMORY_LIMIT,
    });
    return {
      memoryContext: memoryContextBuilder.build({ memories }),
    };
  } catch (error: unknown) {
    const structured = readStructuredError(error);
    if (structured?.code === "DATABASE_ERROR") {
      return {
        memoryContext: memoryContextBuilder.build({ memories: [] }),
        warning: { code: "MEMORY_RETRIEVAL_UNAVAILABLE" },
      };
    }
    if (
      structured?.code === "LIFE_NOT_FOUND" ||
      structured?.code === "MEMORY_LIFE_MISMATCH"
    ) {
      throw new MemoryContextIntegrationError(
        "CONVERSATION_LIFE_NOT_FOUND",
        "The current digital life could not be validated for memory retrieval.",
        false,
      );
    }
    throw error;
  }
}

export function combineConversationSystemContext(
  personaSystemContext: string,
  memoryContext: MemoryContextResult,
): string {
  return combineCognitionContexts(personaSystemContext, memoryContext.context);
}

export class MemoryContextIntegrationError extends Error {
  readonly code: string;
  readonly recoverable: boolean;

  constructor(
    code: string,
    message: string,
    recoverable: boolean,
  ) {
    super(message);
    this.name = "MemoryContextIntegrationError";
    this.code = code;
    this.recoverable = recoverable;
  }
}

function readStructuredError(
  error: unknown,
): { code: string; message: string; recoverable: boolean } | null {
  if (typeof error !== "object" || error === null) {
    return null;
  }
  const candidate = error as Record<string, unknown>;
  if (
    typeof candidate.code !== "string" ||
    typeof candidate.message !== "string" ||
    typeof candidate.recoverable !== "boolean"
  ) {
    return null;
  }
  return {
    code: candidate.code,
    message: candidate.message,
    recoverable: candidate.recoverable,
  };
}
