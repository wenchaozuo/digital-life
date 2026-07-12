import {
  MemoryKinds,
  MemorySourceTypes,
  MemoryStatuses,
  type MemoryKind,
} from "../types.ts";
import type {
  MemoryCandidate,
  MemoryExtractionRequest,
  MemoryExtractionResult,
} from "./types";

interface RuleMatch {
  detail: string;
  importance: number;
  confidence: number;
}

interface ExtractionRule {
  kind: MemoryKind;
  match(sentence: string): RuleMatch | null;
  summarize(detail: string): string;
}

const HARD_SENSITIVE_PATTERNS: readonly RegExp[] = [
  /(?:api[\s_-]*key|access[\s_-]*token|auth[\s_-]*token|token|bearer|密码|口令|password|passcode|验证码|otp)\s*(?:是|为|[:=])/i,
  /(?:身份证号?|护照号?|社会保障号|private[\s_-]*key|私钥|cookie|session[\s_-]*id)/i,
  /(?:银行卡|银行账号|信用卡|借记卡|cvv|iban|routing[\s_-]*number)/i,
  /(?:(?:我的)?地址|住址|家庭地址|详细地址|邮寄地址|我住在).*(?:路|街|号|栋|室|小区|road|street|avenue)/i,
];

const POSSIBLY_SENSITIVE_PATTERNS: readonly RegExp[] = [
  /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/i,
  /(?:^|\D)(?:\+?\d[\d\s-]{8,}\d)(?:\D|$)/,
  /(?:出生日期|生日|date of birth)/i,
];

const RULES: readonly ExtractionRule[] = [
  {
    kind: MemoryKinds.Preference,
    match: (sentence) =>
      matchPatterns(sentence, [
        [
          /^我(?:很|非常|比较)?喜欢(.+)$/u,
          0.72,
          0.95,
          (match) => `喜欢${match[1]}`,
        ],
        [
          /^我不喜欢(.+)$/u,
          0.72,
          0.95,
          (match) => `不喜欢${match[1]}`,
        ],
        [
          /^I\s+(?:really\s+)?(like|love|prefer|dislike)\s+(.+)$/i,
          0.72,
          0.95,
          (match) => `${match[1]} ${match[2]}`,
        ],
      ]),
    summarize: (detail) => `Preference: ${detail}`,
  },
  {
    kind: MemoryKinds.Goal,
    match: (sentence) =>
      matchPatterns(sentence, [
        [/^(?:我的目标是|我要学习|我计划|我打算)(.+)$/u, 0.82, 0.95],
        [/^我想(?:要)?(.+)$/u, 0.68, 0.82],
        [/^I\s+(?:want to|plan to|intend to)\s+(.+)$/i, 0.7, 0.86],
      ]),
    summarize: (detail) => `Goal: ${detail}`,
  },
  {
    kind: MemoryKinds.Relationship,
    match: (sentence) =>
      matchPatterns(sentence, [
        [/^我和(.+?)是(.+)$/u, 0.76, 0.9, (match) => `${match[1]}: ${match[2]}`],
        [/^(.+?)\s+is my\s+(.+)$/i, 0.76, 0.9, (match) => `${match[1]}: ${match[2]}`],
      ]),
    summarize: (detail) => `Relationship: ${detail}`,
  },
  {
    kind: MemoryKinds.Skill,
    match: (sentence) =>
      matchPatterns(sentence, [
        [/^我会(.+)$/u, 0.7, 0.9],
        [/^I\s+(?:can|know how to)\s+(.+)$/i, 0.7, 0.9],
      ]),
    summarize: (detail) => `Skill: ${detail}`,
  },
  {
    kind: MemoryKinds.Experience,
    match: (sentence) =>
      matchPatterns(sentence, [
        [/^(?:我曾经|我去过)(.+)$/u, 0.68, 0.86],
        [/^I\s+(?:once|have)\s+(.+)$/i, 0.68, 0.86],
      ]),
    summarize: (detail) => `Experience: ${detail}`,
  },
  {
    kind: MemoryKinds.Other,
    match: (sentence) =>
      matchPatterns(sentence, [
        [/^我通常(.+)$/u, 0.62, 0.86],
        [/^I\s+usually\s+(.+)$/i, 0.62, 0.86],
      ]),
    summarize: (detail) => `Habit: ${detail}`,
  },
  {
    kind: MemoryKinds.Fact,
    match: (sentence) =>
      matchPatterns(sentence, [
        [/^我是(.+)$/u, 0.74, 0.9],
        [/^我的(.+?)是(.+)$/u, 0.74, 0.9, (match) => `${match[1]}: ${match[2]}`],
        [/^I\s+am\s+(.+)$/i, 0.74, 0.9],
        [/^My\s+(.+?)\s+is\s+(.+)$/i, 0.74, 0.9, (match) => `${match[1]}: ${match[2]}`],
      ]),
    summarize: (detail) => `Fact: ${detail}`,
  },
];

type PatternDefinition = readonly [
  pattern: RegExp,
  importance: number,
  confidence: number,
  detail?: (match: RegExpMatchArray) => string,
];

export class MemoryExtractor {
  extract(request: MemoryExtractionRequest): MemoryExtractionResult {
    validateRequest(request);

    const candidates: MemoryCandidate[] = [];
    const seen = new Set<string>();
    let analyzedMessageCount = 0;
    let rejectedSensitiveCount = 0;

    for (const message of request.messages) {
      if (message.role !== "user") {
        continue;
      }
      analyzedMessageCount += 1;

      for (const sentence of splitSentences(message.content)) {
        if (isHardSensitive(sentence)) {
          rejectedSensitiveCount += 1;
          continue;
        }

        const candidate = extractSentence(
          request.lifeId,
          sentence,
          message.timestamp,
        );
        if (!candidate) {
          continue;
        }

        const deduplicationKey = `${candidate.kind}\u0000${candidate.content}`;
        if (!seen.has(deduplicationKey)) {
          seen.add(deduplicationKey);
          candidates.push(candidate);
        }
      }
    }

    return {
      lifeId: request.lifeId,
      sourceType: MemorySourceTypes.Conversation,
      candidates,
      analyzedMessageCount,
      rejectedSensitiveCount,
    };
  }
}

export class MemoryExtractionError extends Error {
  readonly code: string;
  readonly recoverable: boolean;

  constructor(code: string, message: string, recoverable: boolean) {
    super(message);
    this.name = "MemoryExtractionError";
    this.code = code;
    this.recoverable = recoverable;
  }
}

function validateRequest(request: MemoryExtractionRequest): void {
  if (request.lifeId.trim().length === 0) {
    throw new MemoryExtractionError(
      "MEMORY_EXTRACTION_LIFE_REQUIRED",
      "lifeId must not be empty.",
      true,
    );
  }
  if (request.sourceType !== MemorySourceTypes.Conversation) {
    throw new MemoryExtractionError(
      "MEMORY_EXTRACTION_SOURCE_INVALID",
      "Memory extraction only accepts conversation source data.",
      false,
    );
  }
}

function splitSentences(content: string): string[] {
  return content
    .split(/[。！？!?；;\n]+/u)
    .map((sentence) => sentence.replace(/\s+/g, " ").trim())
    .filter((sentence) => sentence.length > 0);
}

function isHardSensitive(sentence: string): boolean {
  return HARD_SENSITIVE_PATTERNS.some((pattern) => pattern.test(sentence));
}

function isPossiblySensitive(sentence: string): boolean {
  return POSSIBLY_SENSITIVE_PATTERNS.some((pattern) => pattern.test(sentence));
}

function extractSentence(
  lifeId: string,
  sentence: string,
  sourceCreatedAt: string,
): MemoryCandidate | null {
  for (const rule of RULES) {
    const match = rule.match(sentence);
    if (!match || match.detail.length === 0) {
      continue;
    }
    return {
      lifeId,
      kind: rule.kind,
      status: MemoryStatuses.Candidate,
      content: sentence,
      summary: rule.summarize(match.detail),
      importance: match.importance,
      confidence: match.confidence,
      sourceType: MemorySourceTypes.Conversation,
      sourceCreatedAt,
      isSensitive: isPossiblySensitive(sentence),
    };
  }
  return null;
}

function matchPatterns(
  sentence: string,
  definitions: readonly PatternDefinition[],
): RuleMatch | null {
  for (const [pattern, importance, confidence, detail] of definitions) {
    const match = sentence.match(pattern);
    if (!match) {
      continue;
    }
    return {
      detail: (detail ? detail(match) : match[1]).trim(),
      importance,
      confidence,
    };
  }
  return null;
}

export const memoryExtractor = new MemoryExtractor();
