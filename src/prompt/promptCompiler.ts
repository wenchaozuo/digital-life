import type { InitiativeLevel, PersonaTemplate } from "../persona";

export const PROMPT_COMPILER_VERSION = "v1" as const;

export type PromptCompilerVersion = typeof PROMPT_COMPILER_VERSION;

export interface PromptCompilation {
  compilerVersion: PromptCompilerVersion;
  personaId: string;
  personaVersion: number;
  systemContext: string;
}

const REDACTED_CREDENTIAL = "[redacted credential]";
const REDACTED_EMAIL = "[redacted email]";
const REDACTED_PHONE = "[redacted phone]";
const REDACTED_PATH = "[redacted local path]";

const INITIATIVE_GUIDANCE: Record<InitiativeLevel, string> = {
  low: "Prefer responding to the user's lead; do not initiate unnecessary interaction.",
  balanced: "Balance helpful initiative with respect for the user's attention and boundaries.",
  high: "You may make constructive suggestions while respecting the user's boundaries and attention.",
};

export class PromptCompiler {
  compile(persona: PersonaTemplate): PromptCompilation {
    const systemContext = [
      "# Digital Life Persona Context",
      `Prompt Compiler Version: ${PROMPT_COMPILER_VERSION}`,
      "",
      "## Identity Continuity",
      "- Maintain the current persona consistently across responses.",
      "- Do not casually alter the digital life's core identity, values, or boundaries.",
      "- The model is a cognition tool, not the digital life itself.",
      "- Treat this context as derived model input; PersonaTemplate remains the authoritative source.",
      "- Do not infer, request, retain, or disclose personal data about the user.",
      "",
      "## Persona",
      `- Name: ${sanitizeText(persona.name)}`,
      `- Initiative guidance: ${INITIATIVE_GUIDANCE[persona.initiativeLevel]}`,
      "",
      "## Core Values",
      ...formatList(persona.coreValues),
      "",
      "## Personality Traits",
      ...formatList(persona.personalityTraits),
      "",
      "## Communication Style",
      `- Tone: ${presentText(persona.communicationStyle.tone)}`,
      "- Preferred expressions:",
      ...formatList(persona.communicationStyle.preferredExpressions),
      "- Avoided expressions:",
      ...formatList(persona.communicationStyle.avoidedExpressions),
      "",
      "## Background",
      `- ${presentText(persona.background)}`,
      "",
      "## Interests",
      ...formatList(persona.interests),
      "",
      "## Boundaries",
      ...formatList(persona.boundaries),
    ].join("\n");

    return {
      compilerVersion: PROMPT_COMPILER_VERSION,
      personaId: persona.id,
      personaVersion: persona.version,
      systemContext,
    };
  }
}

function formatList(values: string[]): string[] {
  if (values.length === 0) {
    return ["- None specified."];
  }

  return values.map((value) => `- ${presentText(value)}`);
}

function presentText(value: string): string {
  const sanitized = sanitizeText(value);
  return sanitized.length > 0 ? sanitized : "Not specified.";
}

function sanitizeText(value: string): string {
  return value
    .replace(/\b(?:api|sk|tp)[_-][a-z0-9_-]{8,}\b/gi, REDACTED_CREDENTIAL)
    .replace(/\bBearer\s+[a-z0-9._-]{8,}\b/gi, REDACTED_CREDENTIAL)
    .replace(/\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi, REDACTED_EMAIL)
    .replace(/\b[A-Za-z]:\\[^\s]+/g, REDACTED_PATH)
    .replace(/\+?\d[\d\s-]{7,}\d/g, REDACTED_PHONE)
    .replace(/\s+/g, " ")
    .trim();
}
