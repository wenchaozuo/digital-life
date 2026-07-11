import { invoke } from "@tauri-apps/api/core";
import {
  MemoryServiceError,
  toMemoryServiceError,
} from "../memoryService";
import type { MemoryRetrievalResult, RetrievalQuery } from "./types";

export class MemoryRetrieverService {
  async retrieve(
    query: RetrievalQuery,
  ): Promise<readonly MemoryRetrievalResult[]> {
    try {
      return await invoke<MemoryRetrievalResult[]>("retrieve_memories", {
        query,
      });
    } catch (error: unknown) {
      throw toMemoryServiceError(error);
    }
  }
}

export { MemoryServiceError as MemoryRetrieverServiceError };

export const memoryRetrieverService = new MemoryRetrieverService();
