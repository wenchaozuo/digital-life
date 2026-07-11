export const MemoryKinds = {
  Experience: "experience",
  Preference: "preference",
  Fact: "fact",
  Relationship: "relationship",
  Goal: "goal",
  Skill: "skill",
  Other: "other",
} as const;

export type MemoryKind = (typeof MemoryKinds)[keyof typeof MemoryKinds];

export const MemoryStatuses = {
  Candidate: "candidate",
  Confirmed: "confirmed",
} as const;

export type MemoryStatus =
  (typeof MemoryStatuses)[keyof typeof MemoryStatuses];

export const MemorySourceTypes = {
  Manual: "manual",
  Conversation: "conversation",
  System: "system",
  Import: "import",
} as const;

export type MemorySourceType =
  (typeof MemorySourceTypes)[keyof typeof MemorySourceTypes];

export interface MemoryRecord {
  id: string;
  lifeId: string;
  kind: MemoryKind;
  status: MemoryStatus;
  content: string;
  summary?: string;
  sourceType: MemorySourceType;
  sourceRef?: string;
  sourceCreatedAt: string;
  importance: number;
  confidence: number;
  isSensitive: boolean;
  createdAt: string;
  updatedAt: string;
  confirmedAt?: string;
}

export interface CreateMemoryCandidateRequest {
  lifeId: string;
  kind: MemoryKind;
  content: string;
  summary?: string;
  sourceType: MemorySourceType;
  sourceRef?: string;
  sourceCreatedAt: string;
  importance: number;
  confidence: number;
  isSensitive: boolean;
}

export interface UpdateMemoryRequest {
  lifeId: string;
  memoryId: string;
  kind: MemoryKind;
  content: string;
  summary?: string;
  sourceType: MemorySourceType;
  sourceRef?: string;
  sourceCreatedAt: string;
  importance: number;
  confidence: number;
  isSensitive: boolean;
}

export interface ConfirmMemoryRequest {
  lifeId: string;
  memoryId: string;
  userConfirmed: boolean;
  sensitiveConsent: boolean;
}

export interface MemoryQuery {
  lifeId: string;
  status?: MemoryStatus;
  kind?: MemoryKind;
}

export interface DeleteMemoryResult {
  memoryId: string;
  deleted: boolean;
}
